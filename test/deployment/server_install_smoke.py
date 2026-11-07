#!/usr/bin/env python3
"""Exercise the Server installer and bootstrap on a disposable Actions VM.

This writes real system directories and starts systemd. Never run on an existing
host. Local CA only: no public ACME request or external identity provider.
"""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import pwd
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


def run(*args):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=180)
    if result.returncode:
        # Installer output is redirected, so it must never display its secret.
        raise RuntimeError(f'{args[0]} failed: {result.stdout}\n{result.stderr}')
    return result.stdout


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--disposable-ci', action='store_true', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    if not args.disposable_ci or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Requires root on an explicitly disposable GitHub Actions VM.')
    root, state = Path('/etc/argus-c2'), Path('/var/lib/argus-c2-server')
    for target in (root, state, Path('/usr/local/libexec/argus-c2'),
                   Path('/etc/systemd/system/argus-c2-server.service')):
        if os.path.lexists(target):
            raise SystemExit('Refusing to touch an existing ARGUS installation.')
    bundle = args.bundle.resolve(strict=True)
    installer = bundle.parent / 'install-server.py'
    require(installer.is_file(), 'Use the installer packaged beside the release bundle.')
    unit = 'argus-c2-server.service'
    try:
        # The update entry point must reject a new host cleanly, before any
        # download, account creation or service change (the reported regression).
        for component in ('server', 'agent'):
            result = subprocess.run([sys.executable, str(installer), '--update', component, '--language', 'en'],
                                    capture_output=True, text=True, timeout=30)
            require(result.returncode == 1, 'Updating an uninstalled component must fail gracefully.')
            require('is not installed' in result.stderr and 'No package was downloaded' in result.stderr,
                    f'Missing first-install guidance for {component}: {result.stderr}')
            require('Traceback' not in result.stderr, 'Uninstalled component emitted a Python traceback.')
            require(not root.exists() and not state.exists(), 'Update initialized state on an uninstalled host.')
            require(not Path('/var/lib/argus-c2-updates').exists(), 'Rejected update created a misleading backup record.')
        output = run(sys.executable, installer, '--bundle', bundle, '--host', '127.0.0.1', '--tls', 'local-ca')
        secret_file = root / 'setup/bootstrap.token'
        secret = secret_file.read_text().strip()
        require(secret and secret not in output, 'Installer must keep credentials out of captured output.')
        require(f'sudo cat {secret_file}' in output, 'Missing bootstrap retrieval instructions.')
        require(secret_file.stat().st_uid == 0 and stat.S_IMODE(secret_file.stat().st_mode) == 0o600,
                'Bootstrap credential must be root-owned and private.')
        require('active' == run('systemctl', 'is-active', unit).strip(), 'Installed Server is not active.')
        require('argus-server' == run('systemctl', 'show', unit, '-p', 'User', '--value').strip(),
                'Server must run as its dedicated account.')
        origin = 'https://127.0.0.1:9443'
        context = ssl.create_default_context(cafile=str(root / 'console/ca.pem'))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        browser = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                             urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def request(route, body=None, csrf='', expected=200):
            headers = {'Origin': origin, 'X-CSRF-Token': csrf}
            if body is not None:
                headers['Content-Type'] = 'application/json'
            req = urllib.request.Request(origin + route, headers=headers,
                                         data=json.dumps(body).encode() if body is not None else None)
            try:
                response = browser.open(req, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                require(response.code == expected, f'{route}: HTTP {response.code}, expected {expected}')
                data = response.read()
            return json.loads(data) if route.startswith('/v1/') else data

        for attempt in range(30):
            try:
                status = request('/v1/console/auth/status')
                break
            except urllib.error.URLError:
                if attempt == 29:
                    raise
                time.sleep(0.2)
        require(status['state'] == 'SETUP_PENDING', 'Installed Server has no active bootstrap window.')
        require(b'<html' in request('/setup').lower(), 'Compiled setup page is unavailable.')
        csrf = status['csrf_token']
        request('/v1/console/setup/prove', {'secret': 'wrong-bootstrap-code'}, csrf, expected=403)
        setup = request('/v1/console/setup/prove', {'secret': secret}, csrf)
        require(setup['step'] == 'provider', 'Generated bootstrap code did not open provider setup.')
        require(setup['callback_uri'] == origin + '/v1/console/auth/callback', 'Incorrect callback URI.')
        require(request('/v1/console/setup')['step'] == 'provider', 'Setup session was not established.')
        request('/v1/console/admin/users', expected=401)
        replacement = root / 'setup/bootstrap-reissued.token'
        run('/usr/local/libexec/argus-c2/server', 'console-bootstrap', 'issue',
            '-config', root / 'server-local.json', '-out', replacement)
        request('/v1/console/setup', expected=401)
        request('/v1/console/setup/prove', {'secret': secret}, csrf, expected=403)
        require(request('/v1/console/setup/prove', {'secret': replacement.read_text().strip()}, csrf)['step'] == 'provider',
                'Reissued bootstrap code failed against the running Server.')
        require(not Path('/var/lib/argus-c2-agent').exists(), 'Server installer created an Agent identity.')
        identity_files = [root / 'server/ca.pem', root / 'server/ca-key.pem', root / 'server/admin.token',
                          root / 'console/browser-key.pem', root / 'server.json', root / 'server-local.json']
        original_identity = {p: p.read_bytes() for p in identity_files}
        run(sys.executable, installer, '--bundle', bundle, '--update', 'server', '--language', 'en')
        for p, contents in original_identity.items():
            require(p.read_bytes() == contents, 'Server update replaced existing identity or configuration.')
        require(request('/v1/console/auth/status')['state'] == 'SETUP_PENDING', 'Server update reset Console state.')
        require(b'<html' in request('/setup').lower(), 'Console disappeared after update.')

        # Install and enroll a real Agent on this disposable VM, then update it
        # without reenrollment. The Server and Agent paths must remain independent.
        agent_unit = Path('/etc/systemd/system/argus-c2-agent.service')
        agent_unit.write_bytes(Path('deploy/linux/argus-c2-agent.service').read_bytes())
        agent_unit.chmod(0o644)
        sysusers = Path('/etc/sysusers.d/argus-c2-agent.conf')
        sysusers.write_text('u argus-agent - "ARGUS test Agent" /var/lib/argus-c2-agent /usr/sbin/nologin\n')
        sysusers.chmod(0o644)
        run('systemd-sysusers', sysusers)
        agent_account = pwd.getpwnam('argus-agent')
        agent_state = Path('/var/lib/argus-c2-agent')
        agent_state.mkdir(mode=0o700)
        os.chown(agent_state, agent_account.pw_uid, agent_account.pw_gid)
        agent_binary = Path('/usr/local/libexec/argus-c2/agent')
        with tarfile.open(bundle) as archive:
            agent_binary.write_bytes(archive.extractfile('agent-linux-amd64').read())
        agent_binary.chmod(0o755)
        shutil.copyfile(root / 'server/ca.pem', root / 'ca.pem')
        shutil.copyfile('examples/policy.json', root / 'policy.json')
        (root / 'agent.json').write_text(json.dumps({'server': 'https://127.0.0.1:8443', 'ca': str(root / 'ca.pem'),
                                                   'state_dir': str(agent_state), 'policy': str(root / 'policy.json')}))
        for p in (root / 'ca.pem', root / 'policy.json', root / 'agent.json'):
            p.chmod(0o644)
        token = agent_state / 'enroll.token'
        cli = ['/usr/local/libexec/argus-c2/argus', '-server', 'https://127.0.0.1:8443',
               '-ca', root / 'server/ca.pem', '-token-file', root / 'server/admin.token']
        run(*cli, 'enrollment-token', '-out', token)
        os.chown(token, agent_account.pw_uid, agent_account.pw_gid)
        run('runuser', '-u', 'argus-agent', '--', agent_binary, 'enroll', '-config', root / 'agent.json', '-token-file', token)
        token.unlink()
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'argus-c2-agent.service')
        agent_identity = {p: p.read_bytes() for p in (agent_state / 'agent.pem', agent_state / 'agent-key.pem', root / 'agent.json', root / 'policy.json')}
        before_nodes = json.loads(run(*cli, 'nodes'))
        run(sys.executable, installer, '--bundle', bundle, '--update', 'agent', '--language', 'en')
        for p, contents in agent_identity.items():
            require(p.read_bytes() == contents, 'Agent update replaced identity or policy.')
        after_nodes = json.loads(run(*cli, 'nodes'))
        require(len(after_nodes) == 1 and after_nodes[0]['id'] == before_nodes[0]['id'], 'Agent update reenrolled the node.')
        run('systemctl', 'is-active', '--quiet', 'argus-c2-agent.service')
        # A valid archive containing a failing candidate must leave old programs
        # and the live service available. Unit tests also cover failures after replacement.
        with tempfile.TemporaryDirectory(prefix='argus-bad-update-') as temporary:
            bad = Path(temporary) / 'candidate.tar.gz'
            with tarfile.open(bundle) as archive:
                files = {item.name: archive.extractfile(item).read() for item in archive.getmembers()}
            import hashlib, io
            files['server'] = files['server'][:64]
            manifest = json.loads(files['manifest.json'])
            manifest['files']['server'] = {'size': 64, 'sha256': hashlib.sha256(files['server']).hexdigest()}
            files['manifest.json'] = json.dumps(manifest).encode()
            with tarfile.open(bad, 'w:gz') as archive:
                for name, contents in files.items():
                    entry = tarfile.TarInfo(name)
                    entry.size = len(contents)
                    archive.addfile(entry, io.BytesIO(contents))
            result = subprocess.run([sys.executable, str(installer), '--update', 'server', '--bundle', str(bad),
                                     '--sha256', hashlib.sha256(bad.read_bytes()).hexdigest()], capture_output=True, timeout=180)
            require(result.returncode != 0, 'Invalid update candidate was accepted.')
            run('systemctl', 'is-active', '--quiet', unit)
            require(request('/v1/console/auth/status')['state'] == 'SETUP_PENDING', 'Rejected update lost setup state.')
        print('Real installation: HTTPS, bootstrap/reissue, Server and Agent updates, identity preservation and rejected-candidate recovery passed.')
    finally:
        subprocess.run(['systemctl', 'stop', 'argus-c2-agent.service'], capture_output=True, timeout=60)
        subprocess.run(['systemctl', 'disable', '--now', unit], capture_output=True, timeout=60)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error)[-5000:]
        print(message, file=sys.stderr)
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            escaped = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print(f'::error title=Server installation smoke test failed::{escaped}', flush=True)
        sys.exit(1)
