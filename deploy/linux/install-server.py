#!/usr/bin/env python3
"""Install, update or uninstall ARGUS components; never overwrite existing identity.

Only the Python standard library is required. Public certificate issuance uses
Certbot >= 5.3 (standalone HTTP-01); the installer can provision an isolated venv
on Debian/Ubuntu. ROOT is an internal test seam, not a deployment flag.
"""
import argparse
import contextlib
import fcntl
import grp
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit

ROOT = Path('/')
SERVICE = 'argus-c2-server.service'
CERT_NAME = 'argus-console'
ACME_DIRECTORIES = ('/etc/argus-c2/acme', '/var/lib/argus-certbot', '/var/lib/argus-certbot/logs')
MAX_ARCHIVE = 128 * 1024 * 1024
FILES = {'server': 64 << 20, 'argus': 32 << 20, 'agent-linux-amd64': 32 << 20,
         'agent-linux-arm64': 32 << 20, 'argus-c2-server.service': 16384, 'manifest.json': 16384}
ACME = 'https://acme-v02.api.letsencrypt.org/directory'
GITHUB = 'https://github.com/Oreki0504/Argus-C2/releases'
LATEST_RELEASE = 'https://api.github.com/repos/Oreki0504/Argus-C2/releases/latest'
DEFAULT_RELEASE = None  # Replaced by the release builder to pin matching assets.
LANGUAGE = 'en'


class InstallError(Exception):
    pass


class UpdatePreflightError(InstallError):
    """Update was rejected before downloading a bundle or changing a service."""


class ExistingInstallationError(InstallError):
    """Existing identity requires update/restore, not fresh initialization."""


class RestoreError(InstallError):
    """Restore never issues a certificate or resets retained data."""


class CommandError(InstallError):
    def __init__(self, args, result):
        # Never put raw arguments/output (which may include credentials) in the
        # terminal exception. Update failures save details in a private file.
        self.command = Path(args[0]).name
        self.returncode = result.returncode
        self.stdout, self.stderr = result.stdout, result.stderr
        super().__init__(f'{self.command} failed (exit {self.returncode}).')


def text(en, zh):
    return zh if LANGUAGE == 'zh-CN' else en


def choose_language(args, interactive):
    global LANGUAGE
    if args.language:
        LANGUAGE = args.language
    elif interactive and not args.update:
        print('请选择语言 / Choose a language:\n1. 中文\n2. English')
        choice = input('选择 / Select [1/2, default 1]: ').strip() or '1'
        if choice not in ('1', '2'):
            raise InstallError('请选择 1 或 2 / Select 1 or 2.')
        LANGUAGE = 'zh-CN' if choice == '1' else 'en'
    else:
        LANGUAGE = 'en'


def path(value):
    return ROOT / value.lstrip('/')


def run(args, *, check=True, timeout=180, input=None):
    result = subprocess.run([str(a) for a in args], input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if check and result.returncode:
        # CLI diagnostics can include credentials or account URLs. Keep them out
        # of terminal output; Certbot maintains its own root-only diagnostic log.
        raise CommandError(args, result)
    return result


def write_new(dest, data, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(dest, flags, mode)
    with os.fdopen(fd, 'wb') as out:
        os.fchmod(out.fileno(), mode)
        out.write(data.encode() if isinstance(data, str) else data)
        out.flush()
        os.fsync(out.fileno())


def read_bounded(source, limit):
    # Operator-selected certificate sources may be Certbot symlinks. Resolve to
    # a regular file, then pin the final open and bound the read.
    resolved = Path(source).resolve(strict=True)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise InstallError('Input is not a bounded regular file.')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise InstallError('Input exceeds its size limit.')
        return data


def trusted_parents(dest):
    for parent in [dest, *dest.parents]:
        if not parent.is_relative_to(ROOT) or parent == ROOT:
            break
        if parent.is_symlink():
            raise InstallError(f'Installation path is a symlink: {parent}')
        if parent.exists():
            info = parent.stat()
            if not parent.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise InstallError(f'Installation parent must be root-owned and not writable by others: {parent}')


def mkdir(dest, mode=0o755):
    trusted_parents(dest)
    missing = []
    parent = dest
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)  # umask 077 must not hide public parent directories.
    dest.chmod(mode)


def architecture():
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or arch is None:
        raise InstallError('Supported hosts: Linux x86_64 or ARM64 with systemd.')
    return arch


def host_value(raw):
    raw = raw.strip().lower()
    try:
        address = ipaddress.ip_address(raw)
        if address.is_unspecified or address.is_multicast or '%' in raw:
            raise InstallError('Use a reachable host IP, not a listen address or scoped IP.')
        return str(address), address
    except ValueError:
        if len(raw) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', raw):
            raise InstallError('Enter a hostname or IP without a scheme, port or path.')
        if any(len(label) > 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label) for label in raw.split('.')):
            raise InstallError('Invalid DNS hostname.')
        return raw, None


def origin(host, port):
    return f'https://{"[" + host + "]" if ":" in host else host}' + (f':{port}' if port != 443 else '')


def parser():
    p = argparse.ArgumentParser(description='Install ARGUS Server, or update/uninstall/restore a local Server or Agent. Without flags, detect retained data before domain/IP and certificate setup.')
    source = p.add_mutually_exclusive_group()
    source.add_argument('--bundle', type=Path, help='local release archive; defaults to the archive next to this script')
    source.add_argument('--bundle-url', help='HTTPS release archive URL; HTTPS redirects are supported')
    source.add_argument('--release', help='GitHub release tag; normally pinned by the downloaded installer')
    source.add_argument('--release-base', help='HTTPS directory containing a published release and SHA256SUMS')
    p.add_argument('--sha256', help='trusted release archive SHA-256; required for URL downloads')
    p.add_argument('--host', help='reachable Console/Fleet DNS hostname or IP')
    p.add_argument('--tls', choices=('letsencrypt', 'local-ca', 'existing'))
    p.add_argument('--email', help='ACME account contact email')
    p.add_argument('--agree-tos', action='store_true', help='explicitly agree to Let’s Encrypt subscriber terms')
    p.add_argument('--certbot', type=Path, help='use an existing Certbot >= 5.3 executable')
    p.add_argument('--console-cert', type=Path)
    p.add_argument('--console-key', type=Path)
    p.add_argument('--fleet-port', type=int, default=8443)
    p.add_argument('--console-port', type=int, default=443, help='Console HTTPS port (default: 443)')
    action = p.add_mutually_exclusive_group()
    action.add_argument('--update', choices=('server', 'agent'), help='update an installed component while preserving configuration and identity')
    action.add_argument('--uninstall', choices=('server', 'agent'), help='stop and remove a component; preserve configuration, data and identity by default')
    action.add_argument('--restore', choices=('server', 'agent'), help='restore programs from the latest keep-data uninstall and start the retained deployment; no download or certificate issuance')
    p.add_argument('--purge', action='store_true', help='with --uninstall, also delete component configuration, state and dedicated account; historical backups remain')
    p.add_argument('--dry-run', action='store_true', help='with --uninstall, show the plan without changing services or files')
    p.add_argument('--yes', action='store_true', help='with --uninstall, explicitly confirm the printed removal plan without prompting')
    p.add_argument('--language', choices=('zh-CN', 'en'), help='prompt language; interactive sessions ask for this first')
    p.add_argument('--deploy-certificate', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--sync-certificate', action='store_true', help=argparse.SUPPRESS)
    return p


def configure(args, interactive):
    if not args.host and interactive:
        print(text('ARGUS Server installation\n1. Domain (Let’s Encrypt)\n2. IP address', 'ARGUS Server 安装\n1. 域名（Let’s Encrypt）\n2. IP 地址'))
        choice = input(text('Select [1/2]: ', '选择 [1/2]: ')).strip()
        if choice not in ('1', '2'):
            raise InstallError('Select 1 or 2.')
        args.host = input(text('Hostname: ', '域名：') if choice == '1' else text('IP: ', 'IP 地址：')).strip()
        _, address = host_value(args.host)
        if (choice == '2') != (address is not None):
            raise InstallError('The identifier does not match the selected domain/IP mode.')
    if not args.host:
        raise InstallError('--host is required in non-interactive mode.')
    args.host, args.address = host_value(args.host)
    if not all(1 <= port <= 65535 for port in (args.fleet_port, args.console_port)) or args.fleet_port == args.console_port:
        raise InstallError('Choose two different ports between 1 and 65535.')
    if args.console_cert or args.console_key:
        if not args.console_cert or not args.console_key or args.tls not in (None, 'existing'):
            raise InstallError('Existing TLS requires both --console-cert and --console-key, without another TLS mode.')
        args.tls = 'existing'
    if not args.tls and args.address and not args.address.is_global:
        if not interactive:
            raise InstallError('Private IPs cannot use Let’s Encrypt. Select --tls local-ca or provide an existing certificate.')
        print(text('Private IPs cannot receive public CA certificates. A separate local CA can be generated; browsers and Agent hosts must trust it.', '私有 IP 无法申请公开 CA 证书。可生成独立本地 CA；浏览器和 Agent 主机需安装其信任证书。'))
        if input(text('Create local CA? [y/N]: ', '生成本地 CA？[y/N]：')).strip().lower() != 'y':
            raise InstallError('Installation cancelled before changes.')
        args.tls = 'local-ca'
    args.tls = args.tls or 'letsencrypt'
    if args.tls == 'existing' and (not args.console_cert or not args.console_key):
        raise InstallError('Provide both certificate files for existing TLS.')
    if args.tls == 'letsencrypt':
        if args.address and not args.address.is_global:
            raise InstallError('Let’s Encrypt requires a public IP address.')
        if not args.address and '.' not in args.host:
            raise InstallError('Let’s Encrypt requires a publicly resolvable DNS name.')
        if 80 in (args.console_port, args.fleet_port):
            raise InstallError('Port 80 must remain available for ACME HTTP-01 renewals.')
        if interactive:
            print(text('Public TCP 80 must reach this host for issuance and renewal.', '证书申请及续期需要公网 TCP 80 能访问此主机。'))
            args.email = args.email or input(text('ACME account email: ', '证书账户邮箱：')).strip()
            if not args.agree_tos:
                print(text('Let’s Encrypt subscriber terms: ', 'Let’s Encrypt 服务条款：') + 'https://letsencrypt.org/repository/')
                args.agree_tos = input(text('Agree to terms? [y/N]: ', '同意服务条款？[y/N]：')).strip().lower() == 'y'
        if not args.email or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', args.email) or not args.agree_tos:
            raise InstallError('ACME requires --email and explicit --agree-tos consent.')
    return args


def https_url(value):
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment:
        raise InstallError('Downloads require HTTPS without credentials or fragments.')
    return value


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def redirect_request(self, *args, **kwargs):
        # GitHub assets redirect to release-assets.githubusercontent.com. Never
        # downgrade TLS or forward credentials to redirected hosts.
        newurl = kwargs.get('newurl', args[5] if len(args) > 5 else '')
        https_url(newurl)
        return super().redirect_request(*args, **kwargs)


def download(url, destination, limit):
    https_url(url)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    request = urllib.request.Request(url, headers={'User-Agent': 'ARGUS-Installer'})
    opener = urllib.request.build_opener(HTTPSRedirects(), urllib.request.HTTPSHandler(context=context))
    digest = hashlib.sha256()
    with opener.open(request, timeout=30) as source, open(destination, 'xb') as out:
        total, deadline = 0, time.monotonic() + 300
        while True:
            chunk = source.read(min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit or time.monotonic() > deadline:
                raise InstallError('Download exceeds its size or time limit.')
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def archive_digest(sums, filename):
    matches = [line.split()[0] for line in sums.splitlines()
               if len(line.split()) == 2 and line.split()[1] == filename]
    if len(matches) != 1 or not re.fullmatch('[0-9a-fA-F]{64}', matches[0]):
        raise InstallError('SHA256SUMS must identify exactly one valid digest for the selected archive.')
    return matches[0].lower()


def resolve_release(args, stage, arch):
    filename = f'argus-server-linux-{arch}.tar.gz'
    if args.release_base:
        base = https_url(args.release_base.rstrip('/'))
        if urlsplit(base).query:
            raise InstallError('Release directory URL must not contain a query string.')
    else:
        tag = args.release or DEFAULT_RELEASE
        if not tag:
            try:
                download(LATEST_RELEASE, stage / 'release.json', 1024 * 1024)
            except urllib.error.HTTPError as error:
                error.close()
                if error.code == 404:
                    raise InstallError('No stable GitHub Release is published. Use a published preview tag with --release TAG, or provide a local bundle.') from error
                raise
            tag = json.loads((stage / 'release.json').read_text()).get('tag_name')
        if not isinstance(tag, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}', tag):
            raise InstallError('Invalid release tag.')
        base = f'{GITHUB}/download/{tag}'
    try:
        download(base + '/SHA256SUMS', stage / 'SHA256SUMS', 16384)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            raise InstallError('This release has no installation assets. Publish SHA256SUMS and the Server bundles before using its URL.') from error
        raise
    expected = archive_digest((stage / 'SHA256SUMS').read_text(), filename)
    if args.sha256 and args.sha256.lower() != expected:
        raise InstallError('The supplied SHA-256 does not match the release manifest.')
    args.sha256, args.bundle_url = expected, base + '/' + filename


def obtain_bundle(args, stage, arch):
    if not args.bundle_url and not args.bundle:
        local = Path(__file__).resolve().parent / f'argus-server-linux-{arch}.tar.gz'
        if local.is_file() and not args.release and not args.release_base:
            args.bundle = local
        else:
            resolve_release(args, stage, arch)
    if args.bundle_url:
        https_url(args.bundle_url)
        if not args.sha256:
            raise InstallError('--sha256 from a trusted release is required for downloads.')
    else:
        if not args.sha256:
            sums = read_bounded(args.bundle.parent / 'SHA256SUMS', 16384).decode()
            args.sha256 = archive_digest(sums, args.bundle.name)
    if not re.fullmatch('[0-9a-fA-F]{64}', args.sha256):
        raise InstallError('Invalid SHA-256 digest.')
    dest = stage / 'release.tar.gz'
    digest = hashlib.sha256()
    if args.bundle_url:
        print(text(f'Downloading Linux {arch} release bundle…', f'正在下载 Linux {arch} 安装包…'))
        actual = download(args.bundle_url, dest, MAX_ARCHIVE)
        if actual != args.sha256.lower():
            raise InstallError('Bundle SHA-256 mismatch; nothing was executed.')
        return dest
    stream = open(args.bundle, 'rb')
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        stream.close()
        raise InstallError('Bundle must be a regular file.')
    with stream, open(dest, 'xb') as out:
        total, deadline = 0, time.monotonic() + 300
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE or time.monotonic() > deadline:
                raise InstallError('Bundle download exceeds its size or time limit.')
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != args.sha256.lower():
        raise InstallError('Bundle SHA-256 mismatch; nothing was executed.')
    return dest


def unpack_bundle(archive, directory, arch):
    directory.mkdir(mode=0o700)
    seen, hashes = set(), {}
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle:
            if member.name not in FILES or member.name in seen or not member.isfile() or member.size < 1 or member.size > FILES[member.name]:
                raise InstallError('Invalid bundle member; links, paths and unexpected files are forbidden.')
            seen.add(member.name)
            source = bundle.extractfile(member)
            data = source.read(FILES[member.name] + 1)
            if len(data) != member.size:
                raise InstallError('Truncated bundle member.')
            hashes[member.name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            write_new(directory / member.name, data, 0o700 if member.name in ('server', 'argus') else 0o600)
    if seen != set(FILES):
        raise InstallError('Incomplete Server bundle.')
    manifest = json.loads((directory / 'manifest.json').read_text())
    hashes.pop('manifest.json')
    if manifest != {'format': 1, 'os': 'linux', 'arch': arch, 'files': hashes}:
        raise InstallError('Bundle manifest/architecture mismatch.')
    for name in ('server', 'argus', 'agent-linux-amd64', 'agent-linux-arm64'):
        expected = 'arm64' if name == 'agent-linux-arm64' else 'amd64' if name == 'agent-linux-amd64' else arch
        header = (directory / name).read_bytes()[:20]
        if header[:7] != b'\x7fELF\x02\x01\x01' or int.from_bytes(header[18:20], 'little') != (183 if expected == 'arm64' else 62):
            raise InstallError('Bundle binary does not match the required architecture.')


def check_ports(args):
    ports = [args.fleet_port, args.console_port] + ([80] if args.tls == 'letsencrypt' else [])
    family = socket.AF_INET6 if args.address and args.address.version == 6 else socket.AF_INET
    for port in ports:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            try:
                # Match Go's listener: closed connections in TIME_WAIT do not
                # prevent immediate reinstall. listen still rejects a live peer.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', port))
                sock.listen(1)
            except OSError as exc:
                raise InstallError(f'Port {port} is unavailable; existing services were left running.') from exc


def existing_server():
    targets = ['/etc/argus-c2/server', '/etc/argus-c2/console', '/etc/argus-c2/setup',
               '/etc/argus-c2/server.json', '/etc/argus-c2/server-local.json', '/etc/argus-c2/console-install.json',
               '/var/lib/argus-c2-server', '/usr/local/libexec/argus-c2/server', '/usr/local/libexec/argus-c2/argus',
               '/usr/local/share/argus-c2/agents',
               '/etc/sysusers.d/argus-c2-server.conf', '/etc/systemd/system/' + SERVICE,
               '/etc/systemd/system/' + SERVICE + '.d',
               '/etc/systemd/system/argus-console-renew.service', '/etc/systemd/system/argus-console-renew.timer']
    for target in targets:
        dest = path(target)
        trusted_parents(dest.parent)
        if os.path.lexists(dest):
            return dest
    return None


def reject_existing_server(existing):
    raise ExistingInstallationError(text(
        f'Existing Server deployment retained at {existing}. This is not a certificate issuance failure. '
        'After keep-data uninstall use --restore server; for an installed Server use --update server. '
        'Only for a deliberately new identity, use --uninstall server --purge before installing again.',
        f'检测到保留的 Server 部署：{existing}。这不是证书申请失败。'
        '保留数据卸载后请用 --restore server 恢复；已安装的 Server 请用 --update server。'
        '仅在明确需要全新身份时，先执行 --uninstall server --purge，再重新安装。'))


def preflight(args):
    if not path('/run/systemd/system').is_dir():
        raise InstallError('A running systemd host is required.')
    for tool in ('systemctl', 'systemd-sysusers', 'openssl'):
        if not shutil.which(tool):
            raise InstallError(f'Required command missing: {tool}')
    existing = existing_server()
    if existing:
        reject_existing_server(existing)
    helper = path('/usr/local/libexec/argus-c2/install-server.py')
    if os.path.lexists(helper):
        managed_file(helper, 1 << 20)  # The maintenance helper survives uninstall.
    if args.tls == 'letsencrypt':
        # Validate persistent ACME paths before downloading bundles or installing
        # tools. Existing account/certificate state from an early failure is reusable.
        for directory in ACME_DIRECTORIES:
            trusted_parents(path(directory))
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup('argus-server')
        except KeyError:
            continue
        raise InstallError('argus-server already exists; use the documented manual deployment procedure.')
    if run(['systemctl', 'cat', SERVICE], check=False).returncode == 0:
        raise InstallError('An existing Server unit was preserved.')
    check_ports(args)


def certbot_executable(args):
    candidate = str(args.certbot) if args.certbot else shutil.which('certbot')
    private = path('/opt/argus-certbot/bin/certbot')
    if not candidate and private.is_file():
        candidate = str(private)
    if candidate:
        version = run([candidate, '--version']).stdout.decode()
        match = re.search(r'(\d+)\.(\d+)', version)
        if not match or tuple(map(int, match.groups())) < (5, 3):
            raise InstallError('Certbot >= 5.3 is required for reliable profile/IP support. Supply --certbot PATH.')
        candidate = str(Path(candidate).absolute())
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', candidate):
            raise InstallError('Certbot executable path must not contain whitespace or systemd specifiers.')
        # Preserve the launcher name: /snap/bin/certbot dispatches through a symlink.
        return candidate
    # Isolated tooling: do not replace a distro/system Python installation.
    venv = path('/opt/argus-certbot')
    trusted_parents(venv.parent)
    if os.path.lexists(venv):
        raise InstallError('Incomplete /opt/argus-certbot preserved; repair it or supply --certbot PATH.')
    if not shutil.which('apt-get'):
        raise InstallError('Install Certbot >= 5.3 using your distribution instructions, then supply --certbot PATH.')
    print(text('Installing an isolated Certbot environment…', '正在安装独立 Certbot 环境…'))
    run(['apt-get', 'update'], timeout=600)
    run(['apt-get', 'install', '-y', 'python3-venv'], timeout=600)
    run([sys.executable, '-m', 'venv', str(venv)])
    run([venv / 'bin/python', '-m', 'pip', 'install', '--disable-pip-version-check',
         '--index-url', 'https://pypi.org/simple', 'certbot>=5.3,<6'], timeout=600)
    args.certbot = private
    return certbot_executable(args)


def acme_arguments(args, certbot, renew=False):
    command = [certbot, 'renew' if renew else 'certonly', '--non-interactive', '--server', ACME,
               '--config-dir', str(path('/etc/argus-c2/acme')), '--work-dir', str(path('/var/lib/argus-certbot')),
               '--logs-dir', str(path(ACME_DIRECTORIES[2])), '--cert-name', CERT_NAME, '--no-directory-hooks']
    if renew:
        return command + ['--deploy-hook', f'/usr/bin/python3 {path("/usr/local/libexec/argus-c2/install-server.py")} --deploy-certificate']
    command += ['--standalone', '--preferred-challenges', 'http', '--agree-tos', '--email', args.email]
    return command + (['--ip-address', args.host, '--required-profile', 'shortlived'] if args.address else ['--domain', args.host])


def request_certificate(args, certbot):
    try:
        result = run(acme_arguments(args, certbot), check=False, timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise InstallError(text(
            'Certbot did not finish within 300 seconds. Check the ACME log file below before retrying.',
            'Certbot 未在 300 秒内完成。请先检查下方 ACME 日志文件，再决定是否重试。')) from exc
    if result.returncode == 0:
        return
    # Classify only this invocation's output, never a previous attempt's log.
    # Print fixed explanations rather than account URLs or challenge tokens.
    diagnostic = b'\n'.join((result.stdout or b'', result.stderr or b'')).decode(errors='replace').lower()
    types = set(re.findall(r'^\s*type:\s*([a-z]+)\s*$', diagnostic, re.MULTILINE))
    if 'connection' in types:
        message = text(
            'HTTP-01 validation failed: the certificate authority could not connect to the public validation endpoint. '
            'Check the domain/IP target, public TCP 80, cloud and host firewall rules, and NAT forwarding. '
            'A free local port does not prove public reachability.',
            'HTTP-01 验证失败：证书机构无法连接公网验证地址。请核对域名/IP 指向、公网 TCP 80、'
            '云平台和本机防火墙规则，以及 NAT 转发。本机端口空闲不代表公网可达。')
    elif 'dns' in types:
        message = text(
            'HTTP-01 validation failed: the certificate authority reported a DNS error. '
            'Check public A/AAAA records and DNS resolution.',
            'HTTP-01 验证失败：证书机构报告 DNS 错误。请检查公开的 A/AAAA 记录及 DNS 解析。')
    elif 'unauthorized' in types:
        message = text(
            'HTTP-01 validation failed: the certificate authority did not receive the expected challenge response. '
            'Check the domain/IP target and any proxy or HTTP redirect rules.',
            'HTTP-01 验证失败：证书机构未收到预期的验证内容。请检查域名/IP 指向、代理及 HTTP 重定向规则。')
    elif 'could not bind tcp port 80' in diagnostic:
        message = text(
            'Certbot could not listen on TCP 80. Check which process is using the port; existing services were left running.',
            'Certbot 无法监听 TCP 80。请检查端口占用；已有服务未被停止。')
    else:
        message = text(
            'Certbot failed. Check the ACME log file below for the specific error; network failure has not been established.',
            'Certbot 执行失败。请查看下方 ACME 日志文件确定具体原因；不能据此认定是网络故障。')
    raise InstallError(message)


def certificates(args, stage):
    certdir = stage / 'console'
    certdir.mkdir(mode=0o700)
    cert, key = certdir / 'browser.pem', certdir / 'browser-key.pem'
    certbot = None
    if args.tls == 'letsencrypt':
        # /var/log may legitimately be group-writable (e.g. root:syslog 0775).
        # Keep private ACME diagnostics under our own protected state directory,
        # without weakening path checks or changing the system log permissions.
        for directory in ACME_DIRECTORIES:
            mkdir(path(directory), 0o700)
        certbot = certbot_executable(args)
        print(text('Requesting a Let’s Encrypt certificate…', '正在申请 Let’s Encrypt 证书…'))
        request_certificate(args, certbot)
        lineage = path('/etc/argus-c2/acme/live/' + CERT_NAME)
        write_new(cert, read_bounded(lineage / 'fullchain.pem', 65536))
        write_new(key, read_bounded(lineage / 'privkey.pem', 16384))
    elif args.tls == 'existing':
        write_new(cert, read_bounded(args.console_cert, 65536))
        write_new(key, read_bounded(args.console_key, 16384))
    else:
        ca, ca_key = certdir / 'ca.pem', certdir / 'ca-key.pem'
        run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
             '-keyout', ca_key, '-out', ca, '-days', '365', '-subj', '/CN=ARGUS Console Local CA',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
        csr = certdir / 'browser.csr'
        run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
             '-keyout', key, '-out', csr, '-subj', '/CN=ARGUS Console'])
        extension = certdir / 'extensions.cnf'
        write_new(extension, f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName={"IP" if args.address else "DNS"}:{args.host}\n')
        run(['openssl', 'x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key, '-CAcreateserial',
             '-out', cert, '-days', '90', '-extfile', extension])
    validate_certificate(cert, key, args.host)
    return certdir, certbot


def validate_certificate(cert, key, host):
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key, password=b'')
    _, address = host_value(host)
    run(['openssl', 'x509', '-in', cert, '-noout', '-checkend', '300'])
    result = run(['openssl', 'x509', '-in', cert, '-noout', '-checkip' if address else '-checkhost', host])
    # OpenSSL 3.0 returns zero even for a name mismatch. Require the explicit
    # affirmative result as well; newer versions also report failure via status.
    expected = f'{"IP" if address else "Hostname"} {host} does match certificate'.encode('ascii')
    if result.stdout.strip() != expected:
        raise InstallError('Console certificate does not match the configured host.')


def console_flags(args, certdir, artifacts, key=None):
    listen = '[::]' if args.address and args.address.version == 6 else '0.0.0.0'
    return ['-console-listen', f'{listen}:{args.console_port}', '-console-origin', origin(args.host, args.console_port),
            '-console-cert', str(certdir / 'browser.pem'), '-console-key', str(key or certdir / 'browser-key.pem'),
            '-console-installer-dir', str(artifacts), '-console-fleet-origin', origin(args.host, args.fleet_port)]


def write_config(dest, args, state, credentials=False):
    fleet = path('/etc/argus-c2/server')
    secrets = path('/run/credentials/' + SERVICE) if credentials else fleet
    listen = '[::]' if args.address and args.address.version == 6 else '0.0.0.0'
    config = {'listen': f'{listen}:{args.fleet_port}', 'state_dir': str(state), 'certificate': str(fleet / 'server.pem'),
              'ca': str(fleet / 'ca.pem'), 'private_key': str(secrets / ('server-key' if credentials else 'server-key.pem')),
              'issuer_key': str(secrets / ('issuer-key' if credentials else 'ca-key.pem')),
              'admins': str(secrets / ('admins' if credentials else 'admins.json'))}
    write_new(dest, json.dumps(config, indent=2) + '\n', 0o644 if credentials else 0o600)


def install(args, stage, bundle, certdir, certbot):
    init = stage / 'initialized'
    server = bundle / 'server'
    listen = '[::]' if args.address and args.address.version == 6 else '0.0.0.0'
    run([server, 'init', '-dir', init, '-hosts', args.host, '-listen', f'{listen}:{args.fleet_port}'])
    run([server, 'run', '-config', init / 'server.json', '-check', *console_flags(args, certdir, bundle)])
    setup = stage / 'setup'
    setup.mkdir(mode=0o700)
    run([server, 'console-token', 'issue', '-config', init / 'server.json', '-out', setup / 'console.token'])
    # Only after archive, certificates and complete Go configuration validate do
    # we create persistent Server state. Partial failures retain that identity.
    fleet, console, state = path('/etc/argus-c2/server'), path('/etc/argus-c2/console'), path('/var/lib/argus-c2-server')
    binaries, artifacts = path('/usr/local/libexec/argus-c2'), path('/usr/local/share/argus-c2/agents')
    for directory in (fleet, console, binaries, artifacts, path('/etc/sysusers.d'), path('/etc/systemd/system/' + SERVICE + '.d')):
        mkdir(directory)
    mkdir(path('/etc/argus-c2/setup'), 0o700)
    mkdir(state, 0o700)
    for name in ('ca.pem', 'server.pem', 'ca-key.pem', 'server-key.pem', 'admins.json', 'admin.token'):
        write_new(fleet / name, (init / name).read_bytes(), 0o644 if name in ('ca.pem', 'server.pem') else 0o600)
    for name in ('browser.pem', 'browser-key.pem', 'ca.pem', 'ca-key.pem'):
        if (certdir / name).exists():
            write_new(console / name, (certdir / name).read_bytes(), 0o600 if 'key' in name else 0o644)
    for name in ('server', 'argus'):
        write_new(binaries / name, (bundle / name).read_bytes(), 0o755)
    for arch in ('amd64', 'arm64'):
        write_new(artifacts / f'agent-linux-{arch}', (bundle / f'agent-linux-{arch}').read_bytes(), 0o644)
    helper = binaries / 'install-server.py'
    if helper.exists():
        replace_file(helper, Path(__file__).read_bytes(), 0o644)
    else:
        write_new(helper, Path(__file__).read_bytes(), 0o644)
    sysusers = path('/etc/sysusers.d/argus-c2-server.conf')
    write_new(sysusers, 'u argus-server - "Argus diagnostics server" /var/lib/argus-c2-server /usr/sbin/nologin\n', 0o644)
    run(['systemd-sysusers', sysusers])
    account = pwd.getpwnam('argus-server')
    write_new(state / 'argus.db', (init / 'state/argus.db').read_bytes())
    os.chown(state / 'argus.db', account.pw_uid, account.pw_gid)
    os.chown(state, account.pw_uid, account.pw_gid)
    write_new(path('/etc/argus-c2/setup/console.token'), (setup / 'console.token').read_bytes())
    write_config(path('/etc/argus-c2/server.json'), args, state, True)
    write_config(path('/etc/argus-c2/server-local.json'), args, state)
    write_new(path('/etc/argus-c2/console-install.json'), json.dumps({'host': args.host, 'tls': args.tls}) + '\n')
    write_new(path('/etc/systemd/system/' + SERVICE), (bundle / SERVICE).read_bytes(), 0o644)
    flags = console_flags(args, console, artifacts, path('/run/credentials/' + SERVICE + '/console-key'))
    command = [str(binaries / 'server'), 'run', '-config', str(path('/etc/argus-c2/server.json')), *flags]
    # All generated arguments are canonical paths or validated DNS/IP/ports;
    # never interpolate caller-provided shell text into a systemd directive.
    dropin = '[Service]\nLoadCredential=console-key:' + str(console / 'browser-key.pem') + '\nExecStart=\nExecStart=' + ' '.join(command) + '\n'
    if min(args.console_port, args.fleet_port) < 1024:
        dropin += 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'
    write_new(path('/etc/systemd/system/' + SERVICE + '.d/console.conf'), dropin, 0o644)
    if certbot:
        renew = ' '.join('"' + arg.replace('\\', '\\\\').replace('"', '\\"') + '"' for arg in acme_arguments(args, certbot, True))
        sync = f'/usr/bin/python3 {binaries / "install-server.py"} --sync-certificate'
        # Sync after every attempt as well: a successful ACME renewal followed by
        # a failed deploy hook must be retried before the next renewal is due.
        write_new(path('/etc/systemd/system/argus-console-renew.service'), '[Unit]\nDescription=Renew ARGUS Console TLS certificate\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nUMask=0077\nPrivateTmp=true\nNoNewPrivileges=true\nTimeoutStartSec=360\nExecStart=' + renew + '\nExecStopPost=' + sync + '\n', 0o644)
        write_new(path('/etc/systemd/system/argus-console-renew.timer'), '[Unit]\nDescription=Check ARGUS Console certificate renewal every six hours\n\n[Timer]\nOnCalendar=*-*-* 00,06,12,18:00:00\nRandomizedDelaySec=300\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n', 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', SERVICE])
    run(['systemctl', 'is-active', '--quiet', SERVICE])
    if certbot:
        run(['systemctl', 'enable', '--now', 'argus-console-renew.timer'])
        run(['systemctl', 'is-active', '--quiet', 'argus-console-renew.timer'])
    print(text('ARGUS Server installed', 'ARGUS Server 安装完成') + f'\nConsole: {origin(args.host, args.console_port)}/login\nFleet: {origin(args.host, args.fleet_port)}')
    print_setup_instructions()
    print(text('Uninstall (keeps data): ', '卸载（保留数据）：') + f'sudo python3 {helper} --uninstall server')
    if args.tls == 'local-ca':
        print(text('Install this Console CA into browser and Agent-host trust stores: ', '请在浏览器和 Agent 主机的信任库中安装此 Console CA：') + str(console / 'ca.pem'))
        print(text('Local certificates are not publicly trusted and are not ACME-renewed; replace the leaf before 90 days.', '本地证书不受公开信任，也不通过 ACME 续期；请在 90 天到期前更换叶证书。'))


def print_setup_instructions(secret_file=None):
    secret_file = secret_file or path('/etc/argus-c2/setup/console.token')
    print(text('Console administrator login:', 'Console 管理员登录：'))
    print(text('1. Open /login and enter the random administrator token to enter the console.', '1. 打开 /login，输入随机管理员 Token 即可进入后台。'))
    print(text('   Read locally: ', '   在服务器本机读取：') + f'sudo cat {secret_file}')
    if sys.stdin.isatty() and sys.stdout.isatty():
        secret = read_bounded(secret_file, 256).decode('ascii').strip()
        print(text('   Administrator token: ', '   管理员 Token：') + secret)
    print(text('2. Optional: open Account & sign-in in the header to configure and bind Google/GitHub.', '2. 可选：点击顶栏账号名称，在“账号与登录”中配置并绑定 Google/GitHub。'))
    print(text('   Keep this reusable token private. Logout and restart do not invalidate it. This is separate from the CLI admin.token.', '   请妥善保管此可重复登录的 Token。退出或重启不会使其失效；它与 CLI admin.token 不同。'))
    print(text('Agent installers are already published.', 'Agent 安装程序已就绪。'))


def report_failure(error, updating=False):
    # Do not print raw HTTP/ACME exceptions, which can contain request URLs.
    print(str(error) if isinstance(error, InstallError) else f'Installation failed ({type(error).__name__}).', file=sys.stderr)
    if isinstance(error, ExistingInstallationError):
        print(text('No certificate request, download, service change or data reset was performed.',
                   '未申请证书、下载程序、更改服务或重置数据。'), file=sys.stderr)
        return
    if isinstance(error, RestoreError):
        print(text('Restore stopped; retained configuration and identity were not reset. No certificate was requested.',
                   '恢复已中止；保留的配置和身份未重置，也未重新申请证书。'), file=sys.stderr)
        return
    if updating:
        if isinstance(error, UpdatePreflightError):
            print(text('Update stopped during installation checks. No package was downloaded and no service was stopped or changed.', '更新在安装状态检查阶段中止。未下载更新包，也未停止或更改任何服务。'), file=sys.stderr)
            return
        print(text('Update did not complete. Preserve the existing state and inspect the private update records under /var/lib/argus-c2-updates.', '更新未完成。请保留现有状态，并检查 /var/lib/argus-c2-updates 中的私有更新记录。'), file=sys.stderr)
        return
    if not path('/etc/argus-c2/server').exists() and not path('/var/lib/argus-c2-server').exists():
        print(text('Server initialization has not completed; no Console login token was created. Fix the cause and retry; Certbot/ACME state is preserved.', 'Server 尚未初始化，本次没有生成 Console 登录 Token。修复原因后可重试；已有 Certbot 环境及 ACME 状态会保留。'), file=sys.stderr)
    else:
        print(text('Existing Server data was preserved. Inspect: ', '已保留 Server 数据。检查服务：') + 'sudo journalctl -u argus-c2-server -n 50 --no-pager', file=sys.stderr)
        secret_file = path('/etc/argus-c2/setup/console.token')
        if secret_file.is_file():
            print(text('Console token file: ', 'Console Token 文件：') + str(secret_file), file=sys.stderr)
    logfile = path(ACME_DIRECTORIES[2]) / 'letsencrypt.log'
    print(text('ACME log file (if created): ', '证书申请日志文件（若已创建）：') + str(logfile), file=sys.stderr)
    print('sudo tail -n 80 ' + shlex.quote(str(logfile)), file=sys.stderr)


def replace_file(dest, data, mode):
    fd, temporary = tempfile.mkstemp(prefix=dest.name + '.', dir=dest.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, dest)
        directory_fd = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def managed_file(source, limit):
    trusted_parents(source.parent)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise InstallError(f'Expected a root-managed regular file: {source}')
    return read_bounded(source, limit)


def copy_private_tree(source, destination):
    """Snapshot stopped state without following links or copying special files."""
    if source.is_symlink() or not source.is_dir():
        raise InstallError(f'Expected a real state/configuration directory: {source}')
    destination.mkdir(mode=0o700)
    for current, directories, files, directory_fd in os.fwalk(source, follow_symlinks=False):
        target = destination / Path(current).relative_to(source)
        for name in directories:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise InstallError('Update snapshots cannot contain directory symlinks.')
            (target / name).mkdir(mode=0o700)
        for name in files:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            with os.fdopen(fd, 'rb') as incoming:
                if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                    raise InstallError('Update snapshots cannot contain special files.')
                with (target / name).open('xb') as outgoing:
                    os.fchmod(outgoing.fileno(), 0o600)
                    shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())


def database_stamp(state, component):
    name = 'argus.db' if component == 'server' else 'probe.db'
    with contextlib.closing(sqlite3.connect((state / name).as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        deadline = time.monotonic() + 60
        db.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
        if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise InstallError('Database snapshot failed its integrity check; original state was preserved.')
        return (db.execute('PRAGMA application_id').fetchone()[0], db.execute('PRAGMA user_version').fetchone()[0])


def update_account(component, unit_loaded):
    name = 'argus-' + component
    try:
        return pwd.getpwnam(name)
    except KeyError:
        pass
    markers = [f'/etc/argus-c2/{component}.json', f'/var/lib/argus-c2-{component}',
               f'/usr/local/libexec/argus-c2/{component}', f'/etc/sysusers.d/argus-c2-{component}.conf',
               '/etc/sysusers.d/argus-c2.conf', f'/etc/systemd/system/argus-c2-{component}.service',
               f'/etc/systemd/system/argus-c2-{component}.service.d']
    if component == 'server':
        markers += ['/etc/argus-c2/server', '/etc/argus-c2/server-local.json', '/etc/argus-c2/console',
                    '/etc/argus-c2/setup', '/etc/argus-c2/console-install.json',
                    '/usr/local/share/argus-c2/agents',
                    '/etc/systemd/system/argus-console-renew.service', '/etc/systemd/system/argus-console-renew.timer']
    else:
        markers += ['/etc/argus-c2/policy.json', '/etc/argus-c2/ca.pem']
    try:
        grp.getgrnam(name)
        group_exists = True
    except KeyError:
        group_exists = False
    # ACME accounts and the isolated Certbot environment can remain after an
    # early install failure. They do not establish an installed ARGUS service.
    incomplete = unit_loaded or group_exists or any(os.path.lexists(path(p)) for p in markers)
    if incomplete:
        raise UpdatePreflightError(text(
            f'Existing {component} installation records were found, but service account {name} is missing. Preserve the configuration and identity; repair the existing installation using docs/deployment.md before updating.',
            f'发现 {component} 安装记录，但缺少服务账户 {name}。请保留配置和身份，按 docs/deployment.md 修复现有安装后再更新。'))
    if component == 'server':
        raise UpdatePreflightError(text(
            'Server is not installed. --update server requires a completed installation. Run this downloaded script without --update server to install first; existing Certbot/ACME preparation can be reused.',
            '尚未安装 Server，--update server 仅用于已完成的安装。请去掉 --update server 后执行此下载脚本，先完成安装；已有 Certbot/ACME 准备内容可复用。'))
    raise UpdatePreflightError(text(
        'Agent is not installed. Generate an Agent installation command in Console → Management → Agents → Add agent and run it on this host first. Removing --update agent from this script would install a Server instead.',
        '尚未安装 Agent。请先在 Console → 管理 → Agent → 添加 Agent 中生成安装命令，并在此主机执行。直接删除此脚本的 --update agent 参数会改为安装 Server。'))


def update_plan(component, arch):
    try:
        return inspect_update_plan(component, arch)
    except FileNotFoundError as error:
        raise UpdatePreflightError(text(
            f'The {component} installation is incomplete; required path is missing: {error.filename}. Preserve existing configuration and identity and repair the installation before updating.',
            f'{component} 安装不完整，缺少必要路径：{error.filename}。请保留现有配置和身份，修复安装后再更新。')) from error
    except json.JSONDecodeError as error:
        raise UpdatePreflightError(text(
            'An installed configuration file contains invalid JSON. Repair the existing configuration before updating; no service was changed.',
            '现有配置文件包含无效 JSON。请修复配置后再更新；尚未更改任何服务。')) from error
    except InstallError as error:
        raise UpdatePreflightError(str(error)) from error


def inspect_update_plan(component, arch):
    if not path('/run/systemd/system').is_dir():
        raise InstallError('A running systemd host is required.')
    for tool in ('systemctl', 'runuser'):
        if not shutil.which(tool):
            raise InstallError(f'Required command missing: {tool}')
    unit = f'argus-c2-{component}.service'
    load_state = run(['systemctl', 'show', unit, '--property=LoadState', '--value'], check=False).stdout.strip()
    if load_state not in (b'loaded', b'not-found'):
        raise InstallError(text('Cannot determine the installed service state. Inspect systemctl status ' + unit + ' before updating.',
                                '无法确定已安装服务的状态。更新前请检查 systemctl status ' + unit + '。'))
    account = update_account(component, load_state == b'loaded')
    config_file = path(f'/etc/argus-c2/{component}.json')
    config = json.loads(managed_file(config_file, 8192))
    state = path(f'/var/lib/argus-c2-{component}')
    if config.get('state_dir') != str(state):
        raise InstallError('Automatic updates require the standard installer state directory; use the documented manual procedure for custom deployments.')
    trusted_parents(state.parent)
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or info.st_mode & 0o077:
        raise InstallError('Component state must be a private directory owned by its service account.')
    binaries = path('/usr/local/libexec/argus-c2')
    files = [(component if component == 'server' else f'agent-linux-{arch}', binaries / component, 0o755)]
    if component == 'server':
        files += [('argus', binaries / 'argus', 0o755),
                  ('install-server.py', binaries / 'install-server.py', 0o644)]
        files += [(f'agent-linux-{a}', path(f'/usr/local/share/argus-c2/agents/agent-linux-{a}'), 0o644)
                  for a in ('amd64', 'arm64')]
        managed_file(path('/etc/argus-c2/console-install.json'), 4096)
    for _, dest, _ in files:
        managed_file(dest, 64 << 20)
    if load_state != b'loaded':
        raise InstallError(text('The component service is missing. Preserve its existing files and repair the installation before updating.',
                                '缺少对应组件服务。请保留现有文件，修复安装后再更新。'))
    service_user = run(['systemctl', 'show', unit, '--property=User', '--value']).stdout.decode().strip()
    if service_user != account.pw_name:
        raise InstallError('The service does not use the expected dedicated account.')
    active = run(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0
    return {'component': component, 'account': account, 'config': config, 'config_file': config_file,
            'state': state, 'unit': unit, 'files': files, 'active': active}


def validate_update(plan, bundle, snapshot, *, allow_migration=True):
    plan['stage'] = 'checking_database_snapshot'
    component, account = plan['component'], plan['account']
    expected = database_stamp(snapshot, component)
    expected_id = 0x41524753 if component == 'server' else 0x41524741
    if expected[0] != expected_id:
        raise InstallError('Update snapshot belongs to a different component.')
    # Candidate inspection only sees a copy. Agent storage can recover interrupted
    # tasks locally; those writes must never reach the real identity/database.
    with tempfile.TemporaryDirectory(prefix='argus-update-check-', dir=path('/var/tmp')) as temporary:
        validation = Path(temporary)
        copy_private_tree(snapshot, validation / 'state')
        candidate_name = 'server' if component == 'server' else f'agent-linux-{architecture()}'
        write_new(validation / 'candidate', (bundle / candidate_name).read_bytes(), 0o755)
        config = {**plan['config'], 'state_dir': str(validation / 'state')}
        write_new(validation / 'config.json', json.dumps(config))
        for current, directories, files in os.walk(validation):
            os.chown(current, account.pw_uid, account.pw_gid)
            for name in files:
                os.chown(Path(current) / name, account.pw_uid, account.pw_gid)
        migrate = allow_migration and component == 'server' and expected[1] in (102, 103)
        if migrate:
            plan['stage'] = 'migrating_database_copy'
            run(['runuser', '-u', account.pw_name, '--', validation / 'candidate', 'console-migrate',
                 '-config', validation / 'config.json', '-backup', validation / 'before-migration.db'])
            expected = (expected_id, 104)
        plan['stage'] = 'checking_candidate_storage'
        run(['runuser', '-u', account.pw_name, '--', validation / 'candidate', 'storage',
             '-config', validation / 'config.json'])
        if database_stamp(validation / 'state', component) != expected:
            raise InstallError('Automatic updates cannot migrate the database schema. Use the explicit migration procedure.')
        if component == 'server':
            plan['stage'] = 'checking_console_configuration'
            local = json.loads(managed_file(path('/etc/argus-c2/server-local.json'), 8192))
            local['state_dir'] = str(validation / 'state')
            write_new(validation / 'local.json', json.dumps(local))
            dropin = plan.get('restore_dropin')
            if dropin is None:
                dropin = managed_file(path('/etc/systemd/system/argus-c2-server.service.d/console.conf'), 16384).decode()
            commands = [line[len('ExecStart='):] for line in dropin.splitlines() if line.startswith('ExecStart=') and line != 'ExecStart=']
            if len(commands) != 1:
                raise InstallError('Automatic Server updates require the generated Console service configuration.')
            arguments = shlex.split(commands[0])
            if arguments[:4] != [str(path('/usr/local/libexec/argus-c2/server')), 'run', '-config', str(plan['config_file'])]:
                raise InstallError('Custom service commands require the manual update procedure.')
            flags = arguments[4:]
            allowed = {'-console-listen', '-console-origin', '-console-cert', '-console-key', '-console-installer-dir', '-console-fleet-origin'}
            if len(flags) != 12 or set(flags[::2]) != allowed:
                raise InstallError('Custom Console options require the manual update procedure.')
            values = dict(zip(flags[::2], flags[1::2]))
            plan['console_origin'] = values['-console-origin']
            values['-console-key'] = str(path('/etc/argus-c2/console/browser-key.pem'))
            values['-console-installer-dir'] = str(bundle)
            run([validation / 'candidate', 'run', '-check', '-config', validation / 'local.json',
                 *[item for pair in values.items() for item in pair]])
            if migrate:
                upgraded = snapshot.parent / 'upgraded.db'
                with contextlib.closing(sqlite3.connect((validation / 'state/argus.db').as_uri() + '?mode=ro', uri=True)) as source:
                    with contextlib.closing(sqlite3.connect(upgraded)) as dest:
                        source.backup(dest)
                os.chmod(upgraded, 0o600)
                with upgraded.open('rb') as saved:
                    os.fsync(saved.fileno())
                plan['migration_db'] = upgraded
        else:
            plan['stage'] = 'checking_agent_configuration'
            run(['runuser', '-u', account.pw_name, '--', validation / 'candidate', 'run', '-check',
                 '-config', validation / 'config.json'])


def verify_updated_service(plan):
    for _ in range(3):
        time.sleep(1)
        run(['systemctl', 'is-active', '--quiet', plan['unit']])
    if plan['component'] == 'server':
        settings = json.loads(managed_file(path('/etc/argus-c2/console-install.json'), 4096))
        host, _ = host_value(settings['host'])
        listen = plan['config']['listen']
        port = int(listen.rsplit(':', 1)[1])
        context = ssl.create_default_context(cafile=plan['config']['ca'])
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        # Validate the original Fleet identity over loopback, without depending on
        # public DNS/NAT routing or a possibly revoked initial CLI token.
        with socket.create_connection(('::1' if listen.startswith('[') else '127.0.0.1', port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                client = http.client.HTTPConnection(host, timeout=5)
                client.sock = connection
                try:
                    client.request('GET', '/v1/health')
                    response = client.getresponse()
                    if response.status not in (200, 401):
                        raise InstallError('Updated Fleet listener failed its readiness check.')
                    response.read(4096)
                finally:
                    client.close()


def record_failure(backup, plan, error, filename='failure.json'):
    failure = {'stage': plan.get('stage', 'preparing_update'), 'type': type(error).__name__}
    if isinstance(error, CommandError):
        failure.update(command=error.command, exit_code=error.returncode)
    details = {**failure, 'message': str(error)}
    for key in ('stdout', 'stderr'):
        value = getattr(error, key, None)
        if value:
            details[key] = value[-65536:].decode('utf-8', errors='replace') if isinstance(value, bytes) else str(value)[-65536:]
    try:
        write_new(backup / filename, json.dumps(details, indent=2, ensure_ascii=False) + '\n')
        location = str(backup / filename)
    except OSError:
        # Failure to write diagnostics (e.g. full disk) must not prevent rollback.
        location = 'could not write private diagnostic file'
    summary = f"{failure['stage']} ({failure['type']}"
    if isinstance(error, CommandError):
        summary += f': {error.command}, exit {error.returncode}'
    summary += f'). {location}'
    print(text('Failure at stage: ', '失败阶段：') + summary, file=sys.stderr)
    return failure


def update_component(args, plan, bundle):
    component, unit, account = plan['component'], plan['unit'], plan['account']
    backups = path('/var/lib/argus-c2-updates')
    mkdir(backups, 0o700)
    backup = Path(tempfile.mkdtemp(prefix=component + '-', dir=backups))
    programs = backup / 'programs'
    programs.mkdir(mode=0o700)
    records = []
    for index, (name, dest, mode) in enumerate(plan['files']):
        data = managed_file(dest, 64 << 20)
        saved = programs / str(index)
        write_new(saved, data)
        records.append({'path': str(dest), 'saved': str(saved.relative_to(backup)),
                        'mode': stat.S_IMODE(dest.stat().st_mode), 'sha256': hashlib.sha256(data).hexdigest()})
    metadata = {'component': component, 'release': args.release or DEFAULT_RELEASE, 'bundle_sha256': args.sha256,
                'was_active': plan['active'], 'files': records, 'phase': 'prepared'}
    write_new(backup / 'update.json', json.dumps(metadata, indent=2) + '\n')
    print(text(f'Updating {component}; private backup: {backup}', f'正在更新 {component}；私有更新备份：{backup}'))
    stopped, replaced, migrated, candidate_started = False, False, False, False
    try:
        plan['stage'] = 'stopping_service'
        stopped = True
        run(['systemctl', 'stop', unit])
        if run(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0:
            raise InstallError('The component did not stop; no program was replaced.')
        lock_name = 'server.lock' if component == 'server' else 'probe.lock'
        fd = os.open(plan['state'] / lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            os.fchown(lock.fileno(), account.pw_uid, account.pw_gid)
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise InstallError('Another process holds the component state; no program was replaced.') from error
            plan['stage'] = 'backing_up_state'
            copy_private_tree(plan['state'], backup / 'state')
            config_backup = backup / 'configuration'
            config_backup.mkdir(mode=0o700)
            config_names = ['server.json', 'server-local.json', 'server', 'console', 'console-install.json', 'setup'] if component == 'server' else ['agent.json', 'policy.json', 'ca.pem']
            for name in config_names:
                source = path('/etc/argus-c2') / name
                if source.is_dir() and not source.is_symlink():
                    copy_private_tree(source, config_backup / name)
                elif os.path.lexists(source):
                    write_new(config_backup / name, managed_file(source, 65536))
            validate_update(plan, bundle, backup / 'state')
            plan['stage'] = 'replacing_programs'
            metadata['phase'] = 'replacing'
            replace_file(backup / 'update.json', (json.dumps(metadata, indent=2) + '\n').encode(), 0o600)
            replaced = True
            for name, dest, mode in plan['files']:
                data = Path(__file__).read_bytes() if name == 'install-server.py' else (bundle / name).read_bytes()
                replace_file(dest, data, mode)
            if plan.get('migration_db'):
                plan['stage'] = 'applying_schema_migration'
                # Use the migrated, validated copy only while stopped and locked.
                # A durable original snapshot already exists in the backup.
                upgraded_bytes = read_bounded(plan['migration_db'], 1 << 30)
                metadata['phase'] = 'migrating'
                metadata['target_schema'] = 104
                replace_file(backup / 'update.json', (json.dumps(metadata, indent=2) + '\n').encode(), 0o600)
                with contextlib.closing(sqlite3.connect(plan['state'] / 'argus.db', timeout=5)) as db:
                    if db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] != 0:
                        raise InstallError('Database checkpoint is busy; schema was not replaced.')
                for suffix in ('-wal', '-shm'):
                    sidecar = plan['state'] / ('argus.db' + suffix)
                    if os.path.lexists(sidecar):
                        if sidecar.is_symlink() or not sidecar.is_file():
                            raise InstallError('Unexpected database sidecar; preserve state for manual recovery.')
                        sidecar.unlink()
                migrated = True
                replace_file(plan['state'] / 'argus.db', upgraded_bytes, 0o600)
                os.chown(plan['state'] / 'argus.db', account.pw_uid, account.pw_gid)
        if plan['active']:
            plan['stage'] = 'starting_and_verifying_service'
            candidate_started = True
            run(['systemctl', 'start', unit])
            verify_updated_service(plan)
        metadata['phase'] = 'complete'
        replace_file(backup / 'update.json', (json.dumps(metadata, indent=2) + '\n').encode(), 0o600)
    except (Exception, KeyboardInterrupt) as error:
        metadata['failure'] = record_failure(backup, plan, error)
        if migrated:
            # Do not rewind a schema-changing update after traffic may have
            # been accepted, or start an old binary against schema 104.
            run(['systemctl', 'stop', unit], check=False)
            metadata['phase'] = 'migration_needs_recovery'
            metadata['candidate_started'] = candidate_started
            replace_file(backup / 'update.json', (json.dumps(metadata, indent=2) + '\n').encode(), 0o600)
            raise InstallError(f'Schema replacement or service verification failed. New programs and current database were preserved, service stopped. Inspect journalctl -u {unit}; backup: {backup}. Do not restart an older binary or rewind state after traffic was accepted.') from error
        try:
            if replaced:
                run(['systemctl', 'stop', unit])
                for record in records:
                    replace_file(Path(record['path']), read_bounded(backup / record['saved'], 64 << 20), record['mode'])
            if stopped and plan['active']:
                run(['systemctl', 'start', unit])
                verify_updated_service(plan)
            metadata['phase'] = 'rolled_back'
            replace_file(backup / 'update.json', (json.dumps(metadata, indent=2) + '\n').encode(), 0o600)
        except (Exception, KeyboardInterrupt) as recovery_error:
            plan['stage'] = 'restoring_previous_service'
            record_failure(backup, plan, recovery_error, 'recovery-failure.json')
            raise InstallError(f'Update failed and automatic recovery could not complete. Preserve state and inspect {backup}/update.json and journalctl -u {unit}.') from recovery_error
        raise InstallError(f'Update failed; previous programs and service state restored. Database and identity were not reset. Backup: {backup}') from error
    print(text(f'{component} update complete. Configuration and identity preserved; backup: {backup}', f'{component} 更新完成。配置和身份已保留；备份：{backup}'))
    if component == 'server':
        resume_token_setup(plan)
    if not plan['active']:
        print(text('The service was stopped before the update and remains stopped.', '服务更新前已停止，现仍保持停止。'))


def resume_token_setup(plan):
    with contextlib.closing(sqlite3.connect((plan['state'] / 'argus.db').as_uri() + '?mode=ro', uri=True)) as db:
        initialized, recovery = db.execute('SELECT initialized,recovery FROM console_state WHERE id=1').fetchone()
    if initialized or recovery:
        return
    secret_file = path('/etc/argus-c2/setup/console.token')
    if os.path.lexists(secret_file):
        secret_file = secret_file.with_name(f'console-{time.time_ns()}.token')
    run([path('/usr/local/libexec/argus-c2/server'), 'console-token', 'issue',
         '-config', path('/etc/argus-c2/server-local.json'), '-out', secret_file])
    if plan.get('console_origin'):
        print('Console: ' + plan['console_origin'] + '/login')
    print_setup_instructions(secret_file)


def deploy_certificate(require_hook=True):
    settings = json.loads(read_bounded(path('/etc/argus-c2/console-install.json'), 4096))
    lineage = path('/etc/argus-c2/acme/live/' + CERT_NAME)
    if settings['tls'] != 'letsencrypt' or require_hook and os.environ.get('RENEWED_LINEAGE') != str(lineage):
        raise InstallError('Renewal hook is restricted to the configured ARGUS certificate lineage.')
    directory = path('/etc/argus-c2/console')
    with tempfile.TemporaryDirectory(prefix='renew-', dir=directory) as temp:
        stage = Path(temp)
        cert, key = read_bounded(lineage / 'fullchain.pem', 65536), read_bounded(lineage / 'privkey.pem', 16384)
        old_cert = read_bounded(directory / 'browser.pem', 65536)
        old_key = read_bounded(directory / 'browser-key.pem', 16384)
        if (cert, key) == (old_cert, old_key):
            return
        write_new(stage / 'browser.pem', cert)
        write_new(stage / 'browser-key.pem', key)
        validate_certificate(stage / 'browser.pem', stage / 'browser-key.pem', settings['host'])
        try:
            replace_file(directory / 'browser.pem', cert, 0o644)
            replace_file(directory / 'browser-key.pem', key, 0o600)
            run(['systemctl', 'restart', SERVICE])
            run(['systemctl', 'is-active', '--quiet', SERVICE])
        except Exception:
            replace_file(directory / 'browser.pem', old_cert, 0o644)
            replace_file(directory / 'browser-key.pem', old_key, 0o600)
            run(['systemctl', 'restart', SERVICE], check=False)
            raise


def uninstall_paths(component):
    unit = f'argus-c2-{component}.service'
    programs = [f'/usr/local/libexec/argus-c2/{component}',
                f'/etc/systemd/system/{unit}', f'/etc/systemd/system/{unit}.d',
                f'/etc/sysusers.d/argus-c2-{component}.conf']
    data = [f'/etc/argus-c2/{component}.json', f'/var/lib/argus-c2-{component}']
    units = [unit]
    if component == 'server':
        programs += ['/usr/local/libexec/argus-c2/argus', '/usr/local/share/argus-c2/agents',
                     '/etc/systemd/system/argus-console-renew.timer', '/etc/systemd/system/argus-console-renew.service']
        data += ['/etc/argus-c2/server-local.json', '/etc/argus-c2/server', '/etc/argus-c2/console',
                 '/etc/argus-c2/console-install.json', '/etc/argus-c2/setup',
                 '/etc/argus-c2/acme', '/var/lib/argus-certbot']
        units = ['argus-console-renew.timer', 'argus-console-renew.service', *units]
    else:
        data += ['/etc/argus-c2/policy.json', '/etc/argus-c2/ca.pem']
    return [path(p) for p in programs], [path(p) for p in data], units


def removal_path(target, *, allow_links=False):
    """Never traverse redirected parents, mount points or special files."""
    trusted_parents(target.parent)
    if not os.path.lexists(target):
        return
    top = target.lstat()
    if stat.S_ISLNK(top.st_mode) or not (stat.S_ISDIR(top.st_mode) or stat.S_ISREG(top.st_mode)):
        raise InstallError(f'Unexpected uninstall target; use manual removal: {target}')
    entries = [target]
    if target.is_dir():
        for current, directories, files in os.walk(target, followlinks=False):
            entries.extend(Path(current) / name for name in directories + files)
    for entry in entries:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) and allow_links:
            continue  # rmtree unlinks nested ACME links; never follows them.
        if info.st_dev != top.st_dev or os.path.ismount(entry) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise InstallError(f'Unexpected file or mount in uninstall target: {entry}')


def uninstall_component(args, interactive):
    component, purge = args.uninstall, args.purge
    if not path('/run/systemd/system').is_dir() or not shutil.which('systemctl'):
        raise InstallError('Uninstall requires a running Linux/systemd host.')
    programs, data, units = uninstall_paths(component)
    targets = programs + (data if purge else [])
    for target in targets:
        removal_path(target, allow_links=target in data)
    config_file = path(f'/etc/argus-c2/{component}.json')
    state = path(f'/var/lib/argus-c2-{component}')
    if os.path.lexists(config_file):
        config = json.loads(managed_file(config_file, 8192))
        if config.get('state_dir') != str(state):
            raise InstallError('Custom state directories require manual uninstall; no service was changed.')
    if os.path.lexists(state):
        removal_path(state, allow_links=True)
    name = 'argus-' + component
    try:
        account = pwd.getpwnam(name)
    except KeyError:
        account = None
    try:
        group = grp.getgrnam(name)
    except KeyError:
        group = None
    if purge:
        if account and (account.pw_uid == 0 or account.pw_dir != str(state) or
                        Path(account.pw_shell).name not in ('nologin', 'false')):
            raise InstallError('The account is not a standard ARGUS service account; use manual uninstall.')
        if group and (group.gr_gid == 0 or group.gr_mem or
                      any(u.pw_gid == group.gr_gid and u.pw_name != name for u in pwd.getpwall())):
            raise InstallError('The component group is shared; use manual uninstall.')
        for tool, needed in (('userdel', account), ('groupdel', group)):
            if needed and not shutil.which(tool):
                raise InstallError(f'Required command missing: {tool}')
    shared = path('/etc/sysusers.d/argus-c2.conf')
    shared_after = None
    if os.path.lexists(shared):
        original = managed_file(shared, 16384)
        lines = original.decode().splitlines(keepends=True)
        kept = [line for line in lines if not (len(parts := shlex.split(line, comments=True)) >= 2
                                               and parts[0] in ('u', 'g') and parts[1] == name)]
        if kept != lines:
            shared_after = ''.join(kept).encode()
            targets.append(shared)
    loaded = []
    for unit in units:
        status = run(['systemctl', 'show', unit, '--property=LoadState', '--value'], check=False).stdout.strip()
        if status == b'loaded':
            loaded.append(unit)
        elif status != b'not-found':
            raise InstallError(f'Cannot determine service state: {unit}. Inspect it before uninstalling.')
    existing = [p for p in targets if os.path.lexists(p)]
    print(text(f'Uninstall {component}:', f'卸载 {component}：'))
    for unit in loaded:
        print(text('  Stop and disable: ', '  停止并禁用：') + unit)
    for target in existing:
        print(text('  Remove: ', '  删除：') + str(target) if target != shared else
              text('  Remove only this component from: ', '  仅删除此组件的账户定义：') + str(shared))
    if purge:
        print(text('Deletes current configuration, database, certificates, tokens and dedicated account. This cannot be undone by restoring programs.',
                   '将删除当前配置、数据库、证书、Token 和专用账户。恢复程序不能撤销数据删除。'))
    else:
        print(text('Configuration, database, certificates, tokens and service account will be kept.',
                   '保留配置、数据库、证书、Token 和服务账户。'))
    print(text('Historical update/uninstall backups, the maintenance script and Certbot installation are kept.',
               '历史更新/卸载备份、维护脚本和 Certbot 安装环境保留。'))
    if component == 'agent':
        print(text('This does not revoke the Agent identity on the Server; disable it in Management when retiring the host.',
                   '本机卸载不会撤销 Server 上的 Agent 身份；退役主机时请在管理页禁用该 Agent。'))
    if args.dry_run:
        print(text('Dry run: no changes made.', '预览结束，未作任何更改。'))
        return
    if not existing and not loaded and not (purge and (account or group)):
        print(text('No component files or services remain to remove.', '没有需要卸载的组件文件或服务。'))
        return
    if not args.yes:
        if not interactive:
            raise InstallError('Uninstall requires confirmation; use --dry-run to review, then --yes to confirm.')
        expected = f'purge {component}' if purge else 'yes'
        answer = input(text(f'Type "{expected}" to continue: ', f'输入“{expected}”确认：')).strip()
        if answer != expected:
            print(text('Cancelled; no changes made.', '已取消，未作任何更改。'))
            return
    backups = path('/var/lib/argus-c2-uninstall')
    mkdir(backups, 0o700)
    backup = Path(tempfile.mkdtemp(prefix=component + '-', dir=backups))
    record = {'component': component, 'purge': purge, 'phase': 'prepared', 'stage': 'stopping_services', 'targets': [str(p) for p in existing]}
    write_new(backup / 'uninstall.json', json.dumps(record, indent=2) + '\n')
    print(text('Private uninstall record: ', '私有卸载记录：') + str(backup))
    # Only programs/service definitions are archived. Preserved data stays in
    # place. Purge deliberately does not make a new copy of the removed secrets.
    write_new(backup / 'programs.tar', b'')
    with tarfile.open(backup / 'programs.tar', 'w') as archive:
        for target in [*programs, *([shared] if shared_after is not None else [])]:
            if os.path.lexists(target):
                archive.add(target, arcname=str(target.relative_to(ROOT)), recursive=True)
    with (backup / 'programs.tar').open('rb') as saved:
        os.fsync(saved.fileno())
    for directory in (backup, backups):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    try:
        for unit in loaded:
            run(['systemctl', 'disable', '--now', unit])
            status = run(['systemctl', 'show', unit, '--property=ActiveState', '--value']).stdout.strip()
            if status not in (b'inactive', b'failed'):
                raise InstallError(f'Service has not stopped: {unit}; files were not removed.')
        with contextlib.ExitStack() as stack:
            record['stage'] = 'locking_component_state'
            if state.exists():
                lockpath = state / ('server.lock' if component == 'server' else 'probe.lock')
                fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                lock = stack.enter_context(os.fdopen(fd, 'w'))
                if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                    raise InstallError('Unexpected state lock; no files were removed.')
                if account:
                    os.fchown(lock.fileno(), account.pw_uid, account.pw_gid)
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise InstallError('Another process holds the state lock; no files were removed.') from error
            # userdel refuses a still-running account. Do not kill unrelated
            # processes or recursively delete arbitrary account home directories.
            record['stage'] = 'removing_dedicated_account'
            if purge and account:
                run(['userdel', name])
            if purge and group:
                try:
                    grp.getgrnam(name)  # Some userdel implementations remove it.
                except KeyError:
                    pass
                else:
                    run(['groupdel', name])
            record['stage'] = 'removing_component_files'
            for target in existing:
                removal_path(target, allow_links=target in data)
                if target == shared and shared_after:
                    replace_file(shared, shared_after, 0o644)
                elif target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink(missing_ok=True)
        record['stage'] = 'reloading_systemd'
        run(['systemctl', 'daemon-reload'])
        record['phase'] = 'complete'
    except (Exception, KeyboardInterrupt) as error:
        record['failure'] = record_failure(backup, record, error)
        record['phase'] = 'incomplete'
        raise InstallError(f'Uninstall incomplete. Services may be stopped; inspect {backup}/uninstall.json before retrying.')
    finally:
        replace_file(backup / 'uninstall.json', (json.dumps(record, indent=2) + '\n').encode(), 0o600)
    print(text(f'{component} uninstalled. Record: {backup}', f'{component} 卸载完成。记录：{backup}'))
    if not purge:
        print(text('Data remains in place. Use --restore ' + component + ' to resume with the existing certificates and identity, or --uninstall ' + component + ' --purge for a fresh installation.',
                   '数据仍保留在原处。执行 --restore ' + component + ' 可复用原证书和身份恢复；如需全新安装，请执行 --uninstall ' + component + ' --purge。'))


def restore_archive(component):
    directory = path('/var/lib/argus-c2-uninstall')
    trusted_parents(directory)
    records = sorted(directory.glob(component + '-*'), key=lambda p: p.lstat().st_mtime_ns, reverse=True)
    if not records:
        raise InstallError(text('No uninstall archive found. Restore your deployment backup using the manual procedure.',
                                '没有找到卸载归档。请按手动流程恢复部署备份。'))
    backup = records[0]
    trusted_parents(backup)
    if backup.stat().st_mode & 0o077:
        raise InstallError('Uninstall backup must remain private.')
    metadata = json.loads(managed_file(backup / 'uninstall.json', 65536))
    if metadata.get('component') != component or metadata.get('purge') is not False or metadata.get('phase') != 'complete':
        raise InstallError('The latest uninstall was incomplete or purged data. Automatic restore requires a completed keep-data uninstall.')
    return backup


def restore_component(component):
    backup = None
    try:
        backup = restore_archive(component)
        restore_from_archive(component, backup)
    except (Exception, KeyboardInterrupt) as error:
        if backup:
            record_failure(backup, {'stage': 'restoring_deployment'}, error, f'restore-failure-{time.time_ns()}.json')
        raise RestoreError(str(error) if isinstance(error, InstallError) else
                           f'Restore failed ({type(error).__name__}); inspect the private restore record.') from error


def restore_from_archive(component, backup):
    """Restore only archived programs; never extract an archive over identity."""
    if not path('/run/systemd/system').is_dir():
        raise InstallError('Restore requires a running Linux/systemd host.')
    programs, _, units = uninstall_paths(component)
    shared = path('/etc/sysusers.d/argus-c2.conf')
    state, config_file = path(f'/var/lib/argus-c2-{component}'), path(f'/etc/argus-c2/{component}.json')
    config = json.loads(managed_file(config_file, 8192))
    if config.get('state_dir') != str(state):
        raise InstallError('Custom state directories require manual restore.')
    try:
        account = pwd.getpwnam('argus-' + component)
    except KeyError as error:
        raise InstallError('Retained service account is missing; repair ownership using the manual deployment procedure.') from error
    trusted_parents(state.parent)
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or info.st_mode & 0o077:
        raise InstallError('Retained state must be private and owned by its service account.')
    for unit in units:
        status = run(['systemctl', 'show', unit, '--property=ActiveState', '--value']).stdout.strip()
        if status not in (b'inactive', b'failed'):
            raise InstallError(f'{unit} is running or its state is unknown. Use update for an installed component.')
    archive_path = backup / 'programs.tar'
    trusted_parents(archive_path.parent)
    info = archive_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 256 << 20:
        raise InstallError('Expected a private, bounded uninstall archive.')
    entries, directories, total = {}, set(), 0
    with tarfile.open(archive_path) as archive:
        for member in archive:
            name = Path(member.name)
            target = ROOT / name
            allowed = target == shared or any(target == root or target.is_relative_to(root) for root in programs)
            if name.is_absolute() or '..' in name.parts or not allowed or target in entries or target in directories:
                raise InstallError('Unexpected or duplicate path in uninstall archive.')
            if member.isdir():
                directories.add(target)
            elif member.isfile() and 0 <= member.size <= 64 << 20 and total + member.size <= 256 << 20:
                total += member.size
                entries[target] = (archive.extractfile(member).read(), member.mode & 0o777)
            else:
                raise InstallError('Uninstall archive contains a link, special file or oversized file.')
    binary = path('/usr/local/libexec/argus-c2/' + component)
    unit_file = path('/etc/systemd/system/argus-c2-' + component + '.service')
    required = [binary, unit_file]
    dropin = path('/etc/systemd/system/argus-c2-server.service.d/console.conf')
    if component == 'server':
        required += [dropin, path('/usr/local/libexec/argus-c2/argus')]
        required += [path('/usr/local/share/argus-c2/agents/agent-linux-' + arch) for arch in ('amd64', 'arm64')]
    if any(p not in entries for p in required):
        raise InstallError('Uninstall archive is incomplete; use manual recovery.')
    # Legacy sysusers contains both components. Merge only the selected one so
    # restoring Server cannot recreate or replace Agent account definitions.
    if shared in entries:
        selected = []
        for line in entries[shared][0].decode().splitlines(keepends=True):
            parts = shlex.split(line, comments=True)
            if len(parts) >= 2 and parts[0] in ('u', 'g') and parts[1] == account.pw_name:
                selected.append(line)
        current = managed_file(shared, 16384) if os.path.lexists(shared) else b''
        other = []
        for line in current.decode().splitlines(keepends=True):
            parts = shlex.split(line, comments=True)
            if len(parts) >= 2 and parts[1] == account.pw_name:
                if line.strip() not in [s.strip() for s in selected]:
                    raise InstallError('Existing shared account definition conflicts with restore.')
            else:
                other.append(line)
        entries[shared] = ((''.join(other).rstrip('\n') + '\n' + ''.join(selected)).encode(), 0o644)
    for target in directories:
        trusted_parents(target)
    for target, (data, _) in entries.items():
        trusted_parents(target.parent)
        if target != shared and os.path.lexists(target) and managed_file(target, 64 << 20) != data:
            raise InstallError(f'Existing program differs from uninstall archive: {target}. No files were overwritten.')
    print(text('Restoring retained deployment from: ', '正在恢复保留的部署：') + str(backup))
    plan = {'component': component, 'account': account, 'config': config, 'config_file': config_file,
            'state': state, 'unit': units[-1], 'stage': 'checking_restore_archive'}
    if component == 'server':
        plan['restore_dropin'] = entries[dropin][0].decode()
    lockpath = state / ('server.lock' if component == 'server' else 'probe.lock')
    fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise InstallError('Unexpected retained state lock.')
        os.fchown(lock.fileno(), account.pw_uid, account.pw_gid)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InstallError('Another process holds the retained state; no files were restored.') from error
        with tempfile.TemporaryDirectory(prefix='argus-restore-', dir=path('/var/tmp')) as temporary:
            stage = Path(temporary)
            bundle = stage / 'bundle'
            bundle.mkdir(mode=0o700)
            candidate = 'server' if component == 'server' else 'agent-linux-' + architecture()
            write_new(bundle / candidate, entries[binary][0], 0o755)
            if component == 'server':
                for arch in ('amd64', 'arm64'):
                    name = 'agent-linux-' + arch
                    write_new(bundle / name, entries[path('/usr/local/share/argus-c2/agents/' + name)][0], 0o644)
            copy_private_tree(state, stage / 'state')
            # Archived programs must support the CURRENT retained database. Do
            # not downgrade or migrate it merely to get an old binary running.
            validate_update(plan, bundle, stage / 'state', allow_migration=False)
            for directory in sorted(directories, key=lambda p: len(p.parts)):
                mkdir(directory)
            for target, (data, mode) in entries.items():
                mkdir(target.parent)
                if target.exists():
                    if target == shared:
                        replace_file(target, data, mode)
                else:
                    write_new(target, data, mode)
    try:
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', plan['unit']])
        verify_updated_service(plan)
        if component == 'server' and path('/etc/systemd/system/argus-console-renew.timer') in entries:
            run(['systemctl', 'enable', '--now', 'argus-console-renew.timer'])
    except (Exception, KeyboardInterrupt) as error:
        for unit in units:
            run(['systemctl', 'stop', unit], check=False)
        plan['stage'] = 'starting_restored_service'
        record_failure(backup, plan, error, f'restore-failure-{time.time_ns()}.json')
        raise InstallError('Programs restored but service checks failed. Retained data is unchanged; inspect the private restore failure file.') from error
    print(text('Deployment restored using its original programs, certificates and identity. No certificate was requested. Update separately when ready.',
               '已使用原程序、证书和身份恢复部署，未重新申请证书。需要升级时再单独执行更新。'))
    if component == 'server':
        print('Console: ' + plan['console_origin'] + '/login')
        print(text('Use your existing administrator login. Existing token files: /etc/argus-c2/setup/',
                   '使用原管理员登录。已保留的 Token 文件位于 /etc/argus-c2/setup/。'))


def existing_installation_action(args, interactive):
    existing = existing_server()
    if not existing:
        return False
    can_restore = not path('/usr/local/libexec/argus-c2/server').exists() and path('/etc/argus-c2/server.json').is_file()
    if interactive and can_restore:
        try:
            restore_archive('server')  # Explain missing/incomplete archives before prompting.
        except InstallError as error:
            raise ExistingInstallationError(str(error)) from error
        print(text('A keep-data uninstall was detected. Restore the original deployment with its existing certificates, database and identity?',
                   '检测到保留数据的卸载。是否复用原证书、数据库和身份，恢复原部署？'))
        if input(text('Restore? [y/N]: ', '恢复？[y/N]：')).strip().lower() != 'y':
            print(text('Cancelled; retained deployment unchanged.', '已取消，保留的部署未更改。'))
            return True
        restore_component('server')
        return True
    reject_existing_server(existing)


def main(argv=None):
    os.umask(0o077)
    # Root subprocesses use only system paths, not caller-controlled PATH entries.
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin'
    args = parser().parse_args(argv)
    choose_language(args, sys.stdin.isatty() and not (args.deploy_certificate or args.sync_certificate))
    if (args.purge or args.dry_run or args.yes) and not args.uninstall:
        raise InstallError('--purge, --dry-run and --yes require --uninstall server|agent.')
    if (args.uninstall or args.restore) and any((args.update, args.deploy_certificate, args.sync_certificate, args.bundle,
                               args.bundle_url, args.release, args.release_base, args.sha256, args.host, args.tls,
                               args.email, args.agree_tos, args.console_cert, args.console_key, args.certbot)):
        raise InstallError('Uninstall/restore cannot be combined with installation, update or certificate options.')
    if os.geteuid() != 0:
        raise InstallError('Run with sudo or as root.')
    if args.uninstall and args.dry_run:
        uninstall_component(args, sys.stdin.isatty())
        return
    lockpath = path('/run/argus-c2-install.lock' if (args.update or args.uninstall or args.restore) == 'agent' else '/run/argus-c2-server-install.lock')
    fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w'):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallError('Another Server install or certificate deployment is running.') from exc
        if args.uninstall:
            uninstall_component(args, sys.stdin.isatty())
            return
        if args.restore:
            restore_component(args.restore)
            return
        arch = architecture()
        if args.deploy_certificate or args.sync_certificate:
            if args.update:
                raise InstallError('Update and certificate maintenance cannot be combined.')
            deploy_certificate(require_hook=not args.sync_certificate)
            return
        if args.update:
            if args.host or args.tls or args.email or args.agree_tos or args.console_cert or args.console_key or args.certbot:
                raise InstallError('Updates preserve existing TLS and configuration; omit installation-only options.')
            plan = update_plan(args.update, arch)
            with tempfile.TemporaryDirectory(prefix='argus-update-', dir=path('/var/tmp')) as temporary:
                stage = Path(temporary)
                archive = obtain_bundle(args, stage, arch)
                bundle = stage / 'bundle'
                unpack_bundle(archive, bundle, arch)
                update_component(args, plan, bundle)
            return
        if existing_installation_action(args, sys.stdin.isatty()):
            return
        args = configure(args, sys.stdin.isatty())
        preflight(args)
        with tempfile.TemporaryDirectory(prefix='argus-server-install-', dir=path('/var/tmp')) as temporary:
            stage = Path(temporary)
            archive = obtain_bundle(args, stage, arch)
            bundle = stage / 'bundle'
            unpack_bundle(archive, bundle, arch)
            certdir, certbot = certificates(args, stage)
            install(args, stage, bundle, certdir, certbot)


if __name__ == '__main__':
    try:
        main()
    except (InstallError, OSError, ValueError, EOFError, KeyboardInterrupt, tarfile.TarError, subprocess.SubprocessError, sqlite3.Error) as error:
        if any(arg in ('--uninstall', '--restore') or arg.startswith(('--uninstall=', '--restore=')) for arg in sys.argv[1:]):
            print(str(error) if isinstance(error, InstallError) else f'Maintenance failed ({type(error).__name__}); preserve files and inspect the private record, if created.', file=sys.stderr)
        else:
            report_failure(error, updating=any(arg == '--update' or arg.startswith('--update=') for arg in sys.argv[1:]))
        sys.exit(1)
