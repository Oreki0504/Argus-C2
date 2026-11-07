"""Isolated Server installer tests. Never install a service, request ACME, or run apt.

Set ARGUS_SERVER_TEST_BUNDLE to exercise real bundled Go initialization/checks.
Only systemd/account management is mocked in that opt-in integration test.
"""
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import sqlite3
import ssl
import stat
import subprocess
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
import urllib.error
import urllib.request
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

    def test_language_is_selected_before_installation_prompts(self):
        for choice, expected in [('1', '域名'), ('2', 'Hostname')]:
            answers = iter([choice, '1', 'argus.example.com', 'owner@example.com', 'y'])
            transcript = io.StringIO()
            def answer(prompt):
                transcript.write(prompt + '\n')
                return next(answers)
            with patch.object(installer, 'LANGUAGE', 'en'), patch('builtins.input', side_effect=answer), contextlib.redirect_stdout(transcript):
                args = installer.parser().parse_args([])
                installer.choose_language(args, True)
                installer.configure(args, True)
            self.assertTrue(transcript.getvalue().startswith('请选择语言 / Choose a language:'))
            self.assertIn(expected, transcript.getvalue())
        with patch.object(installer, 'LANGUAGE', 'en'), patch('builtins.input') as read:
            installer.choose_language(installer.parser().parse_args(['--language', 'zh-CN']), True)
            self.assertEqual(installer.text('hello', '你好'), '你好')
            read.assert_not_called()

    def update_fixture(self, component='agent', active=True):
        state = installer.path('/var/lib/argus-c2-' + component)
        installer.mkdir(state, 0o700)
        database = state / ('argus.db' if component == 'server' else 'probe.db')
        with contextlib.closing(sqlite3.connect(database)) as db:
            db.executescript('CREATE TABLE preserved(value TEXT); INSERT INTO preserved VALUES("identity"); '
                             f'PRAGMA application_id={0x41524753 if component == "server" else 0x41524741}; '
                             f'PRAGMA user_version={103 if component == "server" else 101};')
        database.chmod(0o600)
        config = installer.path('/etc/argus-c2/' + component + '.json')
        installer.mkdir(config.parent)
        settings = {'state_dir': str(state)}
        installer.write_new(config, json.dumps(settings))
        binary = installer.path('/usr/local/libexec/argus-c2/' + component)
        installer.mkdir(binary.parent)
        installer.write_new(binary, b'old-program', 0o755)
        bundle = self.root / 'update-bundle'
        bundle.mkdir()
        candidate = 'server' if component == 'server' else 'agent-linux-amd64'
        (bundle / candidate).write_bytes(b'new-program')
        account = pwd.getpwuid(os.geteuid())
        plan = {'component': component, 'state': state, 'config': settings, 'config_file': config,
                'unit': f'argus-c2-{component}.service', 'account': account,
                'files': [(candidate, binary, 0o755)], 'active': active}
        args = installer.parser().parse_args(['--update', component, '--release', 'v0.1.0-preview.4'])
        args.sha256 = '0' * 64
        calls = []
        def system(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 3 if command[1] == 'is-active' else 0, b'', b'')
        return args, plan, bundle, system, calls

    def test_update_preserves_identity_and_has_private_durable_snapshot(self):
        args, plan, bundle, system, calls = self.update_fixture()
        before = (plan['state'] / 'probe.db').read_bytes()
        config = plan['config_file'].read_bytes()
        with patch.object(installer, 'run', side_effect=system), patch.object(installer, 'validate_update') as validate, \
                patch.object(installer, 'verify_updated_service') as verify, contextlib.redirect_stdout(io.StringIO()):
            installer.update_component(args, plan, bundle)
        validate.assert_called_once()
        verify.assert_called_once_with(plan)
        self.assertEqual(plan['files'][0][1].read_bytes(), b'new-program')
        self.assertEqual((plan['state'] / 'probe.db').read_bytes(), before)
        self.assertEqual(plan['config_file'].read_bytes(), config)
        backup = next(installer.path('/var/lib/argus-c2-updates').iterdir())
        self.assertEqual((backup / 'state/probe.db').read_bytes(), before)
        self.assertEqual((backup / 'programs/0').read_bytes(), b'old-program')
        self.assertEqual(json.loads((backup / 'update.json').read_text())['phase'], 'complete')
        for target in backup.rglob('*'):
            self.assertEqual(stat.S_IMODE(target.stat().st_mode) & 0o077, 0)
        self.assertIn(['systemctl', 'start', plan['unit']], calls)

    def test_failed_update_restores_old_program_without_rewinding_database(self):
        args, plan, bundle, system, calls = self.update_fixture()
        def fail_health(_plan):
            with contextlib.closing(sqlite3.connect(plan['state'] / 'probe.db')) as db:
                db.execute('INSERT INTO preserved VALUES("newly committed result")')
                db.commit()
            raise installer.InstallError('simulated health failure')
        with patch.object(installer, 'run', side_effect=system), patch.object(installer, 'validate_update'), \
                patch.object(installer, 'verify_updated_service', side_effect=[installer.InstallError('not ready'), None]), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(installer.InstallError, 'previous programs'):
            # Commit a new record just after replacement and before failure.
            actual_replace = installer.replace_file
            def replace(dest, data, mode):
                actual_replace(dest, data, mode)
                if dest == plan['files'][0][1] and data == b'new-program':
                    try:
                        fail_health(plan)
                    except installer.InstallError:
                        pass
            with patch.object(installer, 'replace_file', side_effect=replace):
                installer.update_component(args, plan, bundle)
        self.assertEqual(plan['files'][0][1].read_bytes(), b'old-program')
        with contextlib.closing(sqlite3.connect(plan['state'] / 'probe.db')) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM preserved').fetchone()[0], 2)
        self.assertEqual(calls.count(['systemctl', 'start', plan['unit']]), 2)

    def test_update_rejects_incompatible_candidate_before_replacing_program(self):
        args, plan, bundle, system, calls = self.update_fixture()
        with patch.object(installer, 'run', side_effect=system), \
                patch.object(installer, 'validate_update', side_effect=installer.InstallError('incompatible schema')), \
                patch.object(installer, 'verify_updated_service'), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(installer.InstallError, 'previous programs'):
            installer.update_component(args, plan, bundle)
        self.assertEqual(plan['files'][0][1].read_bytes(), b'old-program')
        self.assertIn(['systemctl', 'start', plan['unit']], calls)

    def test_stopped_component_stays_stopped_after_update(self):
        args, plan, bundle, system, calls = self.update_fixture(active=False)
        with patch.object(installer, 'run', side_effect=system), patch.object(installer, 'validate_update'), \
                patch.object(installer, 'verify_updated_service') as verify, contextlib.redirect_stdout(io.StringIO()):
            installer.update_component(args, plan, bundle)
        verify.assert_not_called()
        self.assertNotIn(['systemctl', 'start', plan['unit']], calls)

    def test_snapshot_rejects_symlinks_and_special_files(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'escape').symlink_to(self.root / 'outside')
        with self.assertRaises(OSError):
            installer.copy_private_tree(source, self.root / 'snapshot1')
        (source / 'escape').unlink()
        os.mkfifo(source / 'pipe')
        with self.assertRaisesRegex(installer.InstallError, 'special files'):
            installer.copy_private_tree(source, self.root / 'snapshot2')

    def test_update_snapshot_detects_wrong_component_and_corruption(self):
        _, plan, _, _, _ = self.update_fixture()
        self.assertEqual(installer.database_stamp(plan['state'], 'agent'), (0x41524741, 101))
        (plan['state'] / 'probe.db').write_bytes(b'corrupt database')
        with self.assertRaises(sqlite3.DatabaseError):
            installer.database_stamp(plan['state'], 'agent')

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

    def test_download_requires_verified_https_and_rejects_redirect_downgrades(self):
        for url, digest in [('http://example.com/a', 'a' * 64), ('https://user:password@example.com/a', 'a' * 64),
                            ('https://example.com/a', None)]:
            args = SimpleNamespace(bundle_url=url, sha256=digest)
            with self.subTest(url=url), self.assertRaises(installer.InstallError):
                installer.obtain_bundle(args, self.root, 'amd64')
        for target in ('http://other.example', 'https://user:password@other.example', 'file:///etc/passwd'):
            with self.assertRaises(installer.InstallError):
                installer.HTTPSRedirects().redirect_request(None, None, 302, '', {}, target)
        request = urllib.request.Request('https://github.com/example/asset')
        redirected = installer.HTTPSRedirects().redirect_request(request, None, 302, '', {}, 'https://release-assets.githubusercontent.com/asset')
        self.assertEqual(redirected.full_url, 'https://release-assets.githubusercontent.com/asset')

    def test_release_installer_pins_matching_assets_and_architecture(self):
        urls = []
        def download(url, destination, limit):
            urls.append(url)
            destination.write_text('a' * 64 + '  argus-server-linux-arm64.tar.gz\n')
        args = installer.parser().parse_args([])
        with patch.object(installer, 'DEFAULT_RELEASE', 'v0.1.0-preview.1'), patch.object(installer, 'download', side_effect=download):
            installer.resolve_release(args, self.root, 'arm64')
        self.assertEqual(urls, [installer.GITHUB + '/download/v0.1.0-preview.1/SHA256SUMS'])
        self.assertEqual(args.bundle_url, installer.GITHUB + '/download/v0.1.0-preview.1/argus-server-linux-arm64.tar.gz')
        self.assertEqual(args.sha256, 'a' * 64)

    def test_missing_release_has_actionable_error_and_no_fabricated_fallback(self):
        args = installer.parser().parse_args([])
        error = urllib.error.HTTPError(installer.LATEST_RELEASE, 404, 'Not found', {}, None)
        with patch.object(installer, 'DEFAULT_RELEASE', None), patch.object(installer, 'download', side_effect=error):
            with self.assertRaisesRegex(installer.InstallError, 'No stable GitHub Release'):
                installer.resolve_release(args, self.root, 'amd64')

    def test_release_digest_rejects_duplicate_missing_and_conflicting_entries(self):
        filename = 'argus-server-linux-amd64.tar.gz'
        for content in ('', 'bad  ' + filename, ('a' * 64 + '  ' + filename + '\n') * 2):
            with self.assertRaises(installer.InstallError):
                installer.archive_digest(content, filename)
        args = installer.parser().parse_args(['--release', '../main'])
        with self.assertRaisesRegex(installer.InstallError, 'Invalid release tag'):
            installer.resolve_release(args, self.root, 'amd64')
        args = installer.parser().parse_args(['--release', 'v1.0.0', '--sha256', 'b' * 64])
        with patch.object(installer, 'download', side_effect=lambda url, dest, limit: dest.write_text('a' * 64 + '  ' + filename)):
            with self.assertRaisesRegex(installer.InstallError, 'does not match'):
                installer.resolve_release(args, self.root, 'amd64')

    def test_real_https_release_download_follows_secure_redirects_and_verifies_bundle(self):
        args = options('--host', '127.0.0.1', '--tls', 'local-ca')
        certdir, _ = installer.certificates(args, self.root)
        archive, digest = make_bundle(self.root)
        content = archive.read_bytes()
        calls = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                if self.path == '/release/SHA256SUMS':
                    body = (digest + '  argus-server-linux-amd64.tar.gz\n').encode()
                elif self.path == '/release/argus-server-linux-amd64.tar.gz':
                    self.send_response(302)
                    self.send_header('Location', '/objects/archive')
                    self.end_headers()
                    return
                elif self.path == '/objects/archive':
                    body = content
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certdir / 'browser.pem', certdir / 'browser-key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f'https://127.0.0.1:{server.server_port}/release'
            args = installer.parser().parse_args(['--release-base', base])
            stage = self.root / 'download'
            stage.mkdir()
            # Trust only this ephemeral fixture CA; production TLS verification
            # is unchanged and no public service or root installation is used.
            with patch.dict(os.environ, SSL_CERT_FILE=str(certdir / 'ca.pem')), contextlib.redirect_stdout(io.StringIO()):
                downloaded = installer.obtain_bundle(args, stage, 'amd64')
                installer.unpack_bundle(downloaded, self.root / 'unpacked', 'amd64')
                with self.assertRaisesRegex(installer.InstallError, 'size or time limit'):
                    installer.download(base + '/SHA256SUMS', self.root / 'oversized', 16)
            self.assertEqual(downloaded.read_bytes(), content)
            self.assertIn('/objects/archive', calls)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

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

    def test_acme_works_with_group_writable_system_logs_and_preserves_retry_state(self):
        logs = installer.path('/var/log')
        installer.mkdir(logs)
        logs.chmod(0o2775)
        (logs / 'existing-log').write_text('preserve')
        installer.mkdir(installer.path('/run/systemd/system'))
        account = installer.path('/etc/argus-c2/acme/accounts')
        installer.mkdir(account, 0o700)
        (account / 'existing-account').write_text('preserve account')
        args = options('--host', 'argus.example.com', '--email', 'owner@example.com', '--agree-tos')
        with patch.object(installer.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(installer.pwd, 'getpwnam', side_effect=KeyError), \
                patch.object(installer.grp, 'getgrnam', side_effect=KeyError), \
                patch.object(installer, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                patch.object(installer, 'check_ports'):
            installer.preflight(args)
        fixture = self.root / 'certificate-fixture'
        fixture.mkdir()
        certdir, _ = installer.certificates(options('--host', args.host, '--tls', 'local-ca'), fixture)
        actual_run, calls = installer.run, []
        def issue(command, **kwargs):
            if str(command[0]) == '/opt/argus-certbot/bin/certbot':
                calls.append(command)
                lineage = installer.path('/etc/argus-c2/acme/live/argus-console')
                installer.mkdir(lineage, 0o700)
                (lineage / 'fullchain.pem').write_bytes((certdir / 'browser.pem').read_bytes())
                (lineage / 'privkey.pem').write_bytes((certdir / 'browser-key.pem').read_bytes())
                return subprocess.CompletedProcess(command, 0, b'', b'')
            return actual_run(command, **kwargs)
        for attempt in range(2):
            stage = self.root / f'attempt-{attempt}'
            stage.mkdir()
            with patch.object(installer, 'certbot_executable', return_value='/opt/argus-certbot/bin/certbot'), \
                    patch.object(installer, 'run', side_effect=issue), contextlib.redirect_stdout(io.StringIO()):
                installer.certificates(args, stage)
        for command in [*calls, installer.acme_arguments(args, '/opt/argus-certbot/bin/certbot', True)]:
            self.assertEqual(command[command.index('--logs-dir') + 1], str(installer.path('/var/lib/argus-certbot/logs')))
        self.assertEqual(stat.S_IMODE(logs.stat().st_mode), 0o2775)
        self.assertEqual((logs / 'existing-log').read_text(), 'preserve')
        self.assertEqual((account / 'existing-account').read_text(), 'preserve account')
        self.assertFalse((logs / 'argus-certbot').exists())
        for directory in installer.ACME_DIRECTORIES:
            self.assertEqual(stat.S_IMODE(installer.path(directory).stat().st_mode), 0o700)

    def test_acme_private_path_validation_happens_in_preflight(self):
        args = options('--host', 'argus.example.com', '--email', 'owner@example.com', '--agree-tos')
        installer.mkdir(installer.path('/run/systemd/system'))
        state = installer.path('/var/lib/argus-certbot')
        installer.mkdir(state, 0o775)
        with patch.object(installer.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(installer, 'run') as run:
            with self.assertRaisesRegex(installer.InstallError, 'not writable by others'):
                installer.preflight(args)
            run.assert_not_called()
        state.chmod(0o700)
        (state / 'logs').symlink_to(self.root)
        with patch.object(installer.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(installer, 'run') as run:
            with self.assertRaisesRegex(installer.InstallError, 'symlink'):
                installer.preflight(args)
            run.assert_not_called()

    def test_existing_private_certbot_is_reused_after_early_failure(self):
        executable = installer.path('/opt/argus-certbot/bin/certbot')
        installer.mkdir(executable.parent)
        executable.write_text('fixture launcher')
        args = installer.parser().parse_args([])
        with patch.object(installer.shutil, 'which', return_value=None), \
                patch.object(installer, 'run', return_value=subprocess.CompletedProcess([], 0, b'certbot 5.3.0\n')) as run:
            self.assertEqual(installer.certbot_executable(args), str(executable))
            run.assert_called_once_with([str(executable), '--version'])

    def test_setup_code_is_visible_only_in_an_interactive_terminal(self):
        secret_file = installer.path('/etc/argus-c2/setup/bootstrap.token')
        installer.mkdir(secret_file.parent, 0o700)
        installer.write_new(secret_file, 'test-only-bootstrap-secret\n')
        for input_tty, output_tty in [(True, True), (True, False), (False, True), (False, False)]:
            output = io.StringIO()
            with self.subTest(stdin=input_tty, stdout=output_tty), \
                    patch.object(installer.sys.stdin, 'isatty', return_value=input_tty), \
                    patch.object(output, 'isatty', return_value=output_tty), contextlib.redirect_stdout(output):
                installer.print_setup_instructions()
            self.assertEqual('test-only-bootstrap-secret' in output.getvalue(), input_tty and output_tty)
            self.assertIn(f'sudo cat {secret_file}', output.getvalue())
            self.assertIn('/setup', output.getvalue())
            self.assertIn('Auth0/OIDC', output.getvalue())

    def test_failure_explains_missing_bootstrap_without_disclosing_secrets(self):
        with contextlib.redirect_stderr(io.StringIO()) as output:
            installer.report_failure(installer.InstallError('test failure'))
        self.assertIn('no Console bootstrap code was created', output.getvalue())
        self.assertIn('/var/lib/argus-certbot/logs', output.getvalue())
        installer.mkdir(installer.path('/etc/argus-c2/server'))
        secret_file = installer.path('/etc/argus-c2/setup/bootstrap.token')
        installer.mkdir(secret_file.parent, 0o700)
        installer.write_new(secret_file, 'test-only-bootstrap-secret\n')
        with contextlib.redirect_stderr(io.StringIO()) as output:
            installer.report_failure(OSError('private diagnostic'))
        self.assertIn('Existing Server data was preserved', output.getvalue())
        self.assertIn(str(secret_file), output.getvalue())
        self.assertNotIn('test-only-bootstrap-secret', output.getvalue())
        self.assertNotIn('private diagnostic', output.getvalue())

    def test_local_ca_certificate_matches_host_and_mismatched_key_is_rejected(self):
        args = options('--host', '192.168.9.40', '--tls', 'local-ca')
        directory, certbot = installer.certificates(args, self.root)
        self.assertIsNone(certbot)
        installer.validate_certificate(directory / 'browser.pem', directory / 'browser-key.pem', args.host)
        with self.assertRaises(installer.InstallError):
            installer.validate_certificate(directory / 'browser.pem', directory / 'browser-key.pem', '192.168.9.41')
        with self.assertRaises(ssl.SSLError):
            installer.validate_certificate(directory / 'browser.pem', directory / 'ca-key.pem', args.host)

    def test_openssl_zero_exit_requires_affirmative_host_match(self):
        # OpenSSL 3.0 exits successfully even when x509 -checkhost/-checkip
        # reports a mismatch. Exercise that behavior on newer OpenSSL too.
        cases = [('argus.example.com', 'Hostname', '-checkhost'),
                 ('192.168.9.40', 'IP', '-checkip'), ('2001:db8::1', 'IP', '-checkip')]
        for host, label, flag in cases:
            outputs = [(f'{label} {host} does match certificate\n'.encode(), True),
                       (f'{label} {host} does NOT match certificate\n'.encode(), False),
                       (f'{label} another.example.com does match certificate\n'.encode(), False),
                       (b'', False)]
            for output, accepted in outputs:
                result = subprocess.CompletedProcess([], 0, stdout=output, stderr=b'')
                with self.subTest(host=host, output=output), patch.object(installer.ssl, 'SSLContext'), \
                        patch.object(installer, 'run', return_value=result) as run:
                    if accepted:
                        installer.validate_certificate('cert.pem', 'key.pem', host)
                    else:
                        with self.assertRaisesRegex(installer.InstallError, 'does not match'):
                            installer.validate_certificate('cert.pem', 'key.pem', host)
                    self.assertEqual(run.call_args.args[0][-2:], [flag, host])

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
