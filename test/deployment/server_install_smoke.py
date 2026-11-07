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
import ssl
import stat
import subprocess
import sys
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
        print('Real Server installation: systemd, verified HTTPS, setup page, bootstrap proof and local reissue passed.')
    finally:
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
