"""Isolated Server installer tests. Never install a service, request ACME, or run apt.

Set ARGUS_SERVER_TEST_BUNDLE to exercise real bundled Go initialization/checks.
Only systemd/account management is mocked in that opt-in integration test.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('server_installer', REPO / 'deploy/linux/install-server.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def elf(arch):
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    data[18:20] = (183 if arch == 'arm64' else 62).to_bytes(2, 'little')
    return bytes(data)


def make_bundle(directory, *, arch='amd64', mutate=None, extra=None):
    files = {'server': elf(arch), 'argus': elf(arch), 'agent-linux-amd64': elf('amd64'),
             'agent-linux-arm64': elf('arm64'), 'argus-c2-server.service': b'[Service]\nUser=argus-server\n'}
    manifest = {'format': 1, 'os': 'linux', 'arch': arch, 'files': {
        name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in files.items()}}
    files['manifest.json'] = json.dumps(manifest).encode()
    if mutate:
        mutate(files)
    archive = directory / 'release.tar.gz'
    with tarfile.open(archive, 'w:gz') as out:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            out.addfile(member, io.BytesIO(data))
        if extra:
            member, data = extra
            out.addfile(member, io.BytesIO(data))
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


def options(*flags):
    return installer.configure(installer.parser().parse_args(list(flags)), False)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='argus-server-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(installer, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_domain_and_public_ip_issue_different_certbot_requests(self):
        domain = options('--host', 'Argus.Example.com', '--email', 'owner@example.com', '--agree-tos')
        ip = options('--host', '8.8.8.8', '--email', 'owner@example.com', '--agree-tos')
        self.assertEqual(domain.host, 'argus.example.com')
        dns_command = installer.acme_arguments(domain, '/usr/bin/certbot')
        ip_command = installer.acme_arguments(ip, '/usr/bin/certbot')
        self.assertIn('--domain', dns_command)
        self.assertNotIn('--ip-address', dns_command)
        self.assertEqual(ip_command[-4:], ['--ip-address', '8.8.8.8', '--required-profile', 'shortlived'])
        self.assertIn('--standalone', ip_command)
        renewal = installer.acme_arguments(ip, '/usr/bin/certbot', True)
        self.assertIn('renew', renewal)
        self.assertIn('--deploy-hook', renewal)
        self.assertNotIn('--force-renewal', renewal)

    def test_private_ip_requires_explicit_local_trust_and_terms_are_not_implicit(self):
        for flags in [('--host', '192.168.9.40'), ('--host', '192.168.9.40', '--tls', 'letsencrypt'),
                      ('--host', 'argus.example.com', '--email', 'owner@example.com')]:
            with self.subTest(flags=flags), self.assertRaises(installer.InstallError):
                options(*flags)
        args = options('--host', '192.168.9.40', '--tls', 'local-ca')
        self.assertEqual(args.tls, 'local-ca')
        self.assertEqual(installer.origin('2001:db8::1', 9443), 'https://[2001:db8::1]:9443')

    def test_interactive_domain_ip_selection_and_private_ip_consent(self):
        cases = [(['1', 'argus.example.com', 'owner@example.com', 'y'], 'letsencrypt'),
                 (['2', '8.8.8.8', 'owner@example.com', 'y'], 'letsencrypt'),
                 (['2', '192.168.9.40', 'y'], 'local-ca')]
        for answers, mode in cases:
            with patch('builtins.input', side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(installer.configure(installer.parser().parse_args([]), True).tls, mode)
        with patch('builtins.input', side_effect=['2', '192.168.9.40', 'n']), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(installer.InstallError):
                installer.configure(installer.parser().parse_args([]), True)

    def test_identifiers_ports_and_certificate_options_are_validated(self):
        for host in ('0.0.0.0', '::', 'bad;cmd', 'bad%host', 'foo\nbar', '-x.example', 'https://x.example', 'a..b', '224.0.0.1'):
            with self.subTest(host=host), self.assertRaises(installer.InstallError):
                installer.host_value(host)
        for flags in [('--fleet-port', '9443'), ('--fleet-port', '0'), ('--console-port', '65536'),
                      ('--console-cert', '/tmp/cert'), ('--tls', 'existing')]:
            with self.subTest(flags=flags), self.assertRaises(installer.InstallError):
                options('--host', 'localhost', '--tls', 'local-ca', *flags)

    def test_bundle_digest_and_local_manifest_resolution(self):
        archive, digest = make_bundle(self.root)
        stage = self.root / 'stage'
        stage.mkdir()
        (self.root / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n')
        args = installer.parser().parse_args(['--bundle', str(archive)])
        copied = installer.obtain_bundle(args, stage, 'amd64')
        installer.unpack_bundle(copied, self.root / 'unpacked', 'amd64')
        self.assertEqual((self.root / 'unpacked/server').read_bytes(), elf('amd64'))
        copied.unlink()
        args.sha256 = '0' * 64
        with self.assertRaisesRegex(installer.InstallError, 'SHA-256 mismatch'):
            installer.obtain_bundle(args, stage, 'amd64')

    def test_archive_rejects_traversal_links_duplicates_and_missing_files(self):
        for kind in ('traversal', 'link', 'duplicate', 'missing', 'changed', 'wrong-arch'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as temp:
                directory = Path(temp)
                extra, mutate = None, None
                if kind in ('traversal', 'link', 'duplicate'):
                    member = tarfile.TarInfo('../outside' if kind == 'traversal' else 'server')
                    member.size = 4
                    if kind == 'link':
                        member.type, member.linkname, member.size = tarfile.SYMTYPE, '/etc/passwd', 0
                    extra = member, b'test'
                elif kind == 'missing':
                    mutate = lambda files: files.pop('argus')
                elif kind == 'changed':
                    mutate = lambda files: files.update(server=b'tampered')
                archive, _ = make_bundle(directory, extra=extra, mutate=mutate, arch='arm64' if kind == 'wrong-arch' else 'amd64')
                with self.assertRaises(installer.InstallError):
                    installer.unpack_bundle(archive, directory / 'unpacked', 'amd64')
                self.assertFalse((directory / 'outside').exists())

    def test_download_requires_verified_https_and_refuses_redirects(self):
        for url, digest in [('http://example.com/a', 'a' * 64), ('https://user:password@example.com/a', 'a' * 64),
                            ('https://example.com/a', None)]:
            args = SimpleNamespace(bundle_url=url, sha256=digest)
            with self.subTest(url=url), self.assertRaises(installer.InstallError):
                installer.obtain_bundle(args, self.root, 'amd64')
        with self.assertRaises(installer.InstallError):
            installer.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example')

    def test_existing_and_symlink_installations_are_preserved(self):
        args = options('--host', '192.168.9.40', '--tls', 'local-ca')
        installer.mkdir(installer.path('/run/systemd/system'))
        sentinel = installer.path('/etc/argus-c2/server')
        installer.mkdir(sentinel)
        (sentinel / 'identity').write_text('preserve')
        with patch.object(installer.shutil, 'which', return_value='/usr/bin/tool'):
            with self.assertRaisesRegex(installer.InstallError, 'Existing installation'):
                installer.preflight(args)
        self.assertEqual((sentinel / 'identity').read_text(), 'preserve')
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / 'redirect').symlink_to(outside)
        with self.assertRaises(installer.InstallError):
            installer.mkdir(self.root / 'redirect/child')
        self.assertFalse((outside / 'child').exists())

    def test_public_parent_permissions_survive_private_umask(self):
        previous = os.umask(0o077)
        try:
            installer.mkdir(self.root / 'usr/local/libexec/argus-c2')
            installer.write_new(self.root / 'public', b'public', 0o644)
            installer.write_new(self.root / 'executable', b'binary', 0o755)
            installer.write_new(self.root / 'private', b'secret', 0o600)
        finally:
            os.umask(previous)
        for name in ('usr', 'usr/local', 'usr/local/libexec', 'usr/local/libexec/argus-c2'):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o755)
        for name, mode in [('public', 0o644), ('executable', 0o755), ('private', 0o600)]:
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), mode)

    def test_occupied_port_prevents_installation(self):
        args = options('--host', '192.168.9.40', '--tls', 'local-ca')
        with patch.object(installer.socket, 'socket') as socket:
            socket.return_value.__enter__.return_value.bind.side_effect = OSError('in use')
            with self.assertRaisesRegex(installer.InstallError, 'Port 8443 is unavailable'):
                installer.check_ports(args)

    def test_certbot_minimum_and_snap_launcher(self):
        args = installer.parser().parse_args(['--certbot', '/snap/bin/certbot'])
        with patch.object(installer, 'run', return_value=SimpleNamespace(stdout=b'certbot 5.3.0\n')):
            self.assertEqual(installer.certbot_executable(args), '/snap/bin/certbot')
        with patch.object(installer, 'run', return_value=SimpleNamespace(stdout=b'certbot 2.9.0\n')):
            with self.assertRaisesRegex(installer.InstallError, 'Certbot >= 5.3'):
                installer.certbot_executable(args)

    def test_local_ca_certificate_matches_host_and_mismatched_key_is_rejected(self):
        args = options('--host', '192.168.9.40', '--tls', 'local-ca')
        directory, certbot = installer.certificates(args, self.root)
        self.assertIsNone(certbot)
        installer.validate_certificate(directory / 'browser.pem', directory / 'browser-key.pem', args.host)
        with self.assertRaises(installer.InstallError):
            installer.validate_certificate(directory / 'browser.pem', directory / 'browser-key.pem', '192.168.9.41')
        with self.assertRaises(ssl.SSLError):
            installer.validate_certificate(directory / 'browser.pem', directory / 'ca-key.pem', args.host)

    def prepare_renewal(self):
        directory = installer.path('/etc/argus-c2/console')
        lineage = installer.path('/etc/argus-c2/acme/live/argus-console')
        installer.mkdir(directory)
        installer.mkdir(lineage)
        (directory / 'browser.pem').write_bytes(b'old-cert')
        (directory / 'browser-key.pem').write_bytes(b'old-key')
        (lineage / 'fullchain.pem').write_bytes(b'new-cert')
        (lineage / 'privkey.pem').write_bytes(b'new-key')
        installer.path('/etc/argus-c2/console-install.json').write_text(json.dumps({'tls': 'letsencrypt', 'host': 'argus.example.com'}))
        return directory, lineage

    def test_renewal_validates_before_publish_and_restarts_server(self):
        directory, lineage = self.prepare_renewal()
        with patch.dict(os.environ, RENEWED_LINEAGE=str(lineage)), patch.object(installer, 'validate_certificate') as validate, patch.object(installer, 'run') as run:
            installer.deploy_certificate()
        validate.assert_called_once()
        self.assertEqual((directory / 'browser-key.pem').read_bytes(), b'new-key')
        self.assertEqual(stat.S_IMODE((directory / 'browser-key.pem').stat().st_mode), 0o600)
        self.assertEqual(run.call_args_list[0].args[0], ['systemctl', 'restart', installer.SERVICE])

    def test_failed_certificate_deployment_restores_previous_pair(self):
        directory, lineage = self.prepare_renewal()
        with patch.dict(os.environ, RENEWED_LINEAGE=str(lineage)), patch.object(installer, 'validate_certificate'), patch.object(installer, 'run', side_effect=[installer.InstallError('restart failed'), None]):
            with self.assertRaises(installer.InstallError):
                installer.deploy_certificate()
        self.assertEqual((directory / 'browser.pem').read_bytes(), b'old-cert')
        self.assertEqual((directory / 'browser-key.pem').read_bytes(), b'old-key')
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ['browser-key.pem', 'browser.pem'])

    def test_periodic_sync_retries_deployment_without_restarting_unchanged_certificates(self):
        directory, _ = self.prepare_renewal()
        with patch.object(installer, 'validate_certificate'), patch.object(installer, 'run') as run:
            installer.deploy_certificate(require_hook=False)
            self.assertEqual(run.call_count, 2)
            run.reset_mock()
            installer.deploy_certificate(require_hook=False)
            run.assert_not_called()
        self.assertEqual((directory / 'browser.pem').read_bytes(), b'new-cert')

    def test_renewal_rejects_another_lineage_or_invalid_certificate(self):
        directory, lineage = self.prepare_renewal()
        with patch.dict(os.environ, RENEWED_LINEAGE='/some/other/certificate'), patch.object(installer, 'run') as run:
            with self.assertRaises(installer.InstallError):
                installer.deploy_certificate()
            run.assert_not_called()
        with patch.dict(os.environ, RENEWED_LINEAGE=str(lineage)), patch.object(installer, 'validate_certificate', side_effect=installer.InstallError('bad cert')), patch.object(installer, 'run') as run:
            with self.assertRaises(installer.InstallError):
                installer.deploy_certificate()
            run.assert_not_called()
        self.assertEqual((directory / 'browser.pem').read_bytes(), b'old-cert')

    @unittest.skipUnless(os.environ.get('ARGUS_SERVER_TEST_BUNDLE'), 'requires built Server bundle')
    def test_real_bundle_initializes_console_and_preserves_identity_on_repeat(self):
        args = options('--host', '127.0.0.1', '--tls', 'local-ca')
        stage = self.root / 'stage'
        stage.mkdir()
        bundle = stage / 'bundle'
        installer.unpack_bundle(Path(os.environ['ARGUS_SERVER_TEST_BUNDLE']), bundle, installer.architecture())
        certdir, _ = installer.certificates(args, stage)
        # The trusted test leaf stands in for an ACME result; never contact a CA.
        args.tls = 'letsencrypt'
        actual_run, calls = installer.run, []
        def isolated_run(command, **kwargs):
            if str(command[0]) in ('systemctl', 'systemd-sysusers'):
                calls.append([str(arg) for arg in command])
                return subprocess.CompletedProcess(command, 0, b'', b'')
            return actual_run(command, **kwargs)
        account = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
        with patch.object(installer, 'run', side_effect=isolated_run), patch.object(installer.pwd, 'getpwnam', return_value=account), contextlib.redirect_stdout(io.StringIO()) as output:
            installer.install(args, stage, bundle, certdir, '/usr/bin/certbot')
        self.assertIn('https://127.0.0.1:9443/setup', output.getvalue())
        config = json.loads(installer.path('/etc/argus-c2/server.json').read_text())
        self.assertEqual(config['listen'], '0.0.0.0:8443')
        self.assertEqual(config['private_key'], str(installer.path('/run/credentials/argus-c2-server.service/server-key')))
        for target in ('/etc/argus-c2/server/admin.token', '/etc/argus-c2/server/ca-key.pem', '/etc/argus-c2/console/browser-key.pem', '/etc/argus-c2/setup/bootstrap.token'):
            self.assertEqual(stat.S_IMODE(installer.path(target).stat().st_mode), 0o600)
        self.assertNotIn(installer.path('/etc/argus-c2/setup/bootstrap.token').read_text().strip(), output.getvalue())
        self.assertIn(['systemctl', 'enable', '--now', 'argus-console-renew.timer'], calls)
        self.assertFalse(installer.path('/var/lib/argus-c2-agent').exists())
        dropin = installer.path('/etc/systemd/system/argus-c2-server.service.d/console.conf').read_text()
        self.assertIn('-console-listen 0.0.0.0:9443', dropin)
        self.assertIn('LoadCredential=console-key:', dropin)
        renewal = installer.path('/etc/systemd/system/argus-console-renew.service').read_text()
        self.assertIn('ExecStopPost=', renewal)
        self.assertIn('--sync-certificate', renewal)
        installer.run([installer.path('/usr/local/libexec/argus-c2/server'), 'run', '-check',
                       '-config', installer.path('/etc/argus-c2/server-local.json'),
                       *installer.console_flags(args, installer.path('/etc/argus-c2/console'),
                                                installer.path('/usr/local/share/argus-c2/agents'))])
        state = installer.path('/var/lib/argus-c2-server/argus.db')
        before = state.read_bytes()
        installer.mkdir(installer.path('/run/systemd/system'))
        with patch.object(installer.shutil, 'which', return_value='/usr/bin/tool'), self.assertRaises(installer.InstallError):
            installer.preflight(args)
        self.assertEqual(state.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
