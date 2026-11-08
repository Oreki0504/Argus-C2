"""Uninstall tests run only inside a temporary filesystem with mocked systemd."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import server_installer_test as fixtures

installer = fixtures.installer


class UninstallerTests(unittest.TestCase):
    setUp = fixtures.InstallerTests.setUp

    def fixture(self):
        installer.mkdir(installer.path('/run/systemd/system'))
        for component in ('server', 'agent'):
            programs, data, _ = installer.uninstall_paths(component)
            for target in programs + data:
                if target.name.endswith(('.json', '.conf', '.pem', '.service', '.timer')) or target.parent.name == 'argus-c2' and target.name in ('server', 'agent', 'argus') and '/usr/' in str(target):
                    installer.mkdir(target.parent)
                    content = json.dumps({'state_dir': str(installer.path('/var/lib/argus-c2-' + component))}) if target.name == component + '.json' else component
                    installer.write_new(target, content)
                else:
                    installer.mkdir(target, 0o700)
                    installer.write_new(target / 'preserved', component)
        helper = installer.path('/usr/local/libexec/argus-c2/install-server.py')
        installer.write_new(helper, b'maintenance helper')
        shared = installer.path('/etc/sysusers.d/argus-c2.conf')
        installer.write_new(shared, 'u argus-server - "server"\nu argus-agent - "agent"\n')
        backup = installer.path('/var/lib/argus-c2-updates/server-existing')
        installer.mkdir(backup, 0o700)
        installer.write_new(backup / 'original', b'old identity')
        return helper, backup

    @contextlib.contextmanager
    def system(self, loaded=True, active=b'inactive', account=None, group=None):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            output = (b'loaded' if loaded else b'not-found') if '--property=LoadState' in command else active
            return subprocess.CompletedProcess(command, 0, output, b'')
        with patch.object(installer, 'run', side_effect=run), \
                patch.object(installer.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(installer.pwd, 'getpwnam', **({'return_value': account} if account else {'side_effect': KeyError})), \
                patch.object(installer.grp, 'getgrnam', **({'return_value': group} if group else {'side_effect': KeyError})), \
                patch.object(installer.pwd, 'getpwall', return_value=[account] if account else []):
            yield calls

    def execute(self, component, *flags, interactive=False):
        args = installer.parser().parse_args(['--uninstall', component, *flags])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            installer.uninstall_component(args, interactive)
        return out.getvalue()

    def test_keep_data_and_other_component_with_restorable_program_archive(self):
        helper, old_backup = self.fixture()
        state = installer.path('/var/lib/argus-c2-server')
        config = installer.path('/etc/argus-c2/server.json').read_bytes()
        with self.system() as calls:
            self.execute('server', '--yes')
        self.assertEqual((state / 'preserved').read_text(), 'server')
        self.assertEqual(installer.path('/etc/argus-c2/server.json').read_bytes(), config)
        self.assertTrue(installer.path('/etc/argus-c2/setup/preserved').exists())
        self.assertTrue(installer.path('/usr/local/libexec/argus-c2/agent').exists())
        self.assertTrue(installer.path('/etc/systemd/system/argus-c2-agent.service').exists())
        self.assertTrue(helper.exists() and old_backup.exists())
        self.assertFalse(installer.path('/usr/local/libexec/argus-c2/server').exists())
        self.assertFalse(any(c[0] in ('userdel', 'groupdel') for c in calls))
        self.assertEqual(installer.path('/etc/sysusers.d/argus-c2.conf').read_text(), 'u argus-agent - "agent"\n')
        backup = next(installer.path('/var/lib/argus-c2-uninstall').iterdir())
        with tarfile.open(backup / 'programs.tar') as archive:
            self.assertIn('usr/local/libexec/argus-c2/server', archive.getnames())
            self.assertNotIn('var/lib/argus-c2-server', archive.getnames())
        self.assertEqual(stat.S_IMODE((backup / 'programs.tar').stat().st_mode), 0o600)
        self.assertEqual(json.loads((backup / 'uninstall.json').read_text())['phase'], 'complete')
        self.assertEqual(calls[3], ['systemctl', 'disable', '--now', 'argus-console-renew.timer'])

    def test_purge_is_component_scoped_and_does_not_follow_nested_links(self):
        helper, backup = self.fixture()
        outside = self.root / 'outside'
        outside.write_text('unrelated data')
        installer.path('/var/lib/argus-c2-agent/link').symlink_to(outside)
        account = SimpleNamespace(pw_name='argus-agent', pw_uid=os.geteuid(), pw_gid=os.getegid(),
                                  pw_dir=str(installer.path('/var/lib/argus-c2-agent')), pw_shell='/usr/sbin/nologin')
        group = SimpleNamespace(gr_gid=os.getegid(), gr_mem=[])
        with self.system(account=account, group=group) as calls:
            self.execute('agent', '--purge', '--yes')
        for target in installer.uninstall_paths('agent')[0:2]:
            for entry in target:
                self.assertFalse(entry.exists(), str(entry))
        self.assertEqual(outside.read_text(), 'unrelated data')
        self.assertTrue(installer.path('/usr/local/libexec/argus-c2/server').exists())
        self.assertTrue(installer.path('/var/lib/argus-c2-server/preserved').exists())
        self.assertTrue(helper.exists() and backup.exists())
        self.assertIn(['userdel', 'argus-agent'], calls)
        self.assertIn(['groupdel', 'argus-agent'], calls)

    def test_dry_run_and_cancel_do_not_write_or_stop_services(self):
        self.fixture()
        before = sorted(str(p) for p in self.root.rglob('*'))
        with self.system() as calls:
            self.assertIn('Dry run', self.execute('server', '--purge', '--dry-run'))
            with patch('builtins.input', return_value='no'):
                self.assertIn('Cancelled', self.execute('server', '--purge', interactive=True))
            with self.assertRaisesRegex(installer.InstallError, 'requires confirmation'):
                self.execute('agent')
        self.assertTrue(all(c[1] == 'show' for c in calls))
        self.assertEqual(sorted(str(p) for p in self.root.rglob('*')), before)

    def test_partial_install_cleanup_and_repeated_uninstall(self):
        installer.mkdir(installer.path('/run/systemd/system'))
        target = installer.path('/etc/argus-c2/acme')
        installer.mkdir(target, 0o700)
        installer.write_new(target / 'account', b'acme identity')
        with self.system(loaded=False):
            self.execute('server', '--purge', '--yes')
            self.assertIn('No component files', self.execute('server', '--purge', '--yes'))
        self.assertFalse(target.exists())

    def test_server_purge_allows_fresh_install_with_retained_maintenance_helper(self):
        self.fixture()
        with self.system(loaded=False):
            self.execute('server', '--purge', '--yes')
            args = installer.parser().parse_args(['--host', '127.0.0.1', '--tls', 'local-ca'])
            with patch.object(installer, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'')), \
                    patch.object(installer, 'check_ports'):
                installer.preflight(args)

    def test_redirected_target_or_custom_state_is_rejected_before_service_change(self):
        self.fixture()
        binary = installer.path('/usr/local/libexec/argus-c2/server')
        binary.unlink()
        binary.symlink_to(self.root / 'outside')
        with self.system() as calls:
            with self.assertRaisesRegex(installer.InstallError, 'Unexpected uninstall target'):
                self.execute('server', '--yes')
            self.assertEqual(calls, [])
        binary.unlink()
        config = installer.path('/etc/argus-c2/server.json')
        config.write_text(json.dumps({'state_dir': '/custom'}))
        with self.system() as calls:
            with self.assertRaisesRegex(installer.InstallError, 'Custom state'):
                self.execute('server', '--purge', '--yes')
            self.assertEqual(calls, [])

    def test_running_service_or_locked_database_prevents_file_removal(self):
        self.fixture()
        binary = installer.path('/usr/local/libexec/argus-c2/server')
        with self.system(active=b'active'), self.assertRaisesRegex(installer.InstallError, 'incomplete'):
            self.execute('server', '--purge', '--yes')
        self.assertTrue(binary.exists())
        with installer.path('/var/lib/argus-c2-server/server.lock').open('w') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.system(), self.assertRaisesRegex(installer.InstallError, 'incomplete'):
                self.execute('server', '--purge', '--yes')
        self.assertTrue(binary.exists())

    def test_purge_refuses_repurposed_account(self):
        self.fixture()
        account = SimpleNamespace(pw_uid=0, pw_dir='/root', pw_shell='/bin/bash')
        with self.system(account=account) as calls:
            with self.assertRaisesRegex(installer.InstallError, 'not a standard'):
                self.execute('server', '--purge', '--yes')
            self.assertEqual(calls, [])

    def restore_fixture(self, component='server'):
        self.fixture()
        installer.mkdir(installer.path('/var/tmp'))
        installer.write_new(installer.path('/etc/systemd/system/argus-c2-server.service.d/console.conf'), b'console settings')
        for arch in ('amd64', 'arm64'):
            installer.write_new(installer.path('/usr/local/share/argus-c2/agents/agent-linux-' + arch), b'agent binary')
        with self.system():
            self.execute(component, '--yes')
        account = SimpleNamespace(pw_name='argus-' + component, pw_uid=os.geteuid(), pw_gid=os.getegid())
        return account, installer.restore_archive(component)

    def test_restore_reuses_identity_and_preserves_other_component(self):
        account, backup = self.restore_fixture()
        state = installer.path('/var/lib/argus-c2-server/preserved')
        before = state.read_bytes()
        shared = installer.path('/etc/sysusers.d/argus-c2.conf')
        shared.write_text('u argus-agent - "updated agent definition"\n')
        def validate(plan, *_args, **kwargs):
            self.assertFalse(kwargs['allow_migration'])
            plan['console_origin'] = 'https://argus.example.test:9443'
        with self.system(account=account) as calls, patch.object(installer, 'validate_update', side_effect=validate), \
                patch.object(installer, 'verify_updated_service'), contextlib.redirect_stdout(io.StringIO()) as out:
            installer.restore_component('server')
        self.assertEqual(state.read_bytes(), before)
        self.assertEqual(installer.path('/usr/local/libexec/argus-c2/server').read_bytes(), b'server')
        self.assertIn('updated agent definition', shared.read_text())
        self.assertEqual(shared.read_text().count('u argus-server'), 1)
        self.assertTrue(installer.path('/usr/local/libexec/argus-c2/agent').exists())
        self.assertIn(['systemctl', 'enable', '--now', 'argus-console-renew.timer'], calls)
        self.assertFalse(any('argus-c2-agent.service' in c for c in calls))
        self.assertIn('https://argus.example.test:9443/login', out.getvalue())
        self.assertTrue((backup / 'programs.tar').exists())

    def test_restore_agent_checks_schema_without_migrating(self):
        account, _ = self.restore_fixture('agent')
        with self.system(account=account) as calls, patch.object(installer, 'validate_update') as validate, \
                patch.object(installer, 'verify_updated_service'), contextlib.redirect_stdout(io.StringIO()):
            installer.restore_component('agent')
        self.assertFalse(validate.call_args.kwargs['allow_migration'])
        self.assertIn(['systemctl', 'enable', '--now', 'argus-c2-agent.service'], calls)
        self.assertFalse(any('argus-c2-server.service' in c for c in calls))

    def test_restore_refuses_purge_archive_and_archive_path_escape(self):
        account, backup = self.restore_fixture()
        metadata = json.loads((backup / 'uninstall.json').read_text())
        metadata['purge'] = True
        (backup / 'uninstall.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(installer.InstallError, 'purged'):
            installer.restore_archive('server')
        metadata['purge'] = False
        (backup / 'uninstall.json').write_text(json.dumps(metadata))
        with tarfile.open(backup / 'programs.tar', 'a') as archive:
            member = tarfile.TarInfo('../../outside')
            member.size = 3
            archive.addfile(member, io.BytesIO(b'bad'))
        with self.system(account=account), self.assertRaisesRegex(installer.RestoreError, 'Unexpected'):
            installer.restore_component('server')
        self.assertFalse(installer.path('/usr/local/libexec/argus-c2/server').exists())

    def test_restore_validation_failure_does_not_restore_programs_or_reset_data(self):
        account, _ = self.restore_fixture()
        with self.system(account=account), patch.object(installer, 'validate_update', side_effect=installer.InstallError('schema mismatch')), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(installer.RestoreError, 'schema mismatch'):
            installer.restore_component('server')
        self.assertFalse(installer.path('/usr/local/libexec/argus-c2/server').exists())
        self.assertEqual(installer.path('/var/lib/argus-c2-server/preserved').read_bytes(), b'server')

    def test_default_install_offers_restore_before_configuration_and_can_cancel(self):
        self.restore_fixture()
        args = installer.parser().parse_args([])
        with patch('builtins.input', return_value='y'), patch.object(installer, 'restore_component') as restore, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(installer.existing_installation_action(args, True))
            restore.assert_called_once_with('server')
        with patch('builtins.input', return_value='n'), patch.object(installer, 'restore_component') as restore, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(installer.existing_installation_action(args, True))
            restore.assert_not_called()
        with self.assertRaisesRegex(installer.ExistingInstallationError, '--restore server'):
            installer.existing_installation_action(args, False)

    def test_existing_deployment_error_does_not_report_acme_failure(self):
        self.fixture()
        with contextlib.redirect_stderr(io.StringIO()) as out:
            try:
                installer.existing_installation_action(installer.parser().parse_args([]), False)
            except installer.ExistingInstallationError as error:
                installer.report_failure(error)
        self.assertIn('--restore server', out.getvalue())
        self.assertNotIn('letsencrypt.log', out.getvalue())
