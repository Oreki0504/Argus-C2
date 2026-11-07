#!/usr/bin/env python3
"""Install a new ARGUS Server from a verified release; never overwrite a deployment.

Only the Python standard library is required. Public certificate issuance uses
Certbot >= 5.3 (standalone HTTP-01); the installer can provision an isolated venv
on Debian/Ubuntu. ROOT is an internal test seam, not a deployment flag.
"""
import argparse
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import socket
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
MAX_ARCHIVE = 128 * 1024 * 1024
FILES = {'server': 64 << 20, 'argus': 32 << 20, 'agent-linux-amd64': 32 << 20,
         'agent-linux-arm64': 32 << 20, 'argus-c2-server.service': 16384, 'manifest.json': 16384}
ACME = 'https://acme-v02.api.letsencrypt.org/directory'
GITHUB = 'https://github.com/Oreki0504/Argus-C2/releases'
LATEST_RELEASE = 'https://api.github.com/repos/Oreki0504/Argus-C2/releases/latest'
DEFAULT_RELEASE = None  # Replaced by the release builder to pin matching assets.


class InstallError(Exception):
    pass


def path(value):
    return ROOT / value.lstrip('/')


def run(args, *, check=True, timeout=180, input=None):
    result = subprocess.run([str(a) for a in args], input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if check and result.returncode:
        # CLI diagnostics can include credentials or account URLs. Keep them out
        # of terminal output; Certbot maintains its own root-only diagnostic log.
        raise InstallError(f'{Path(args[0]).name} {args[1]} failed; no success was recorded.')
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
    return f'https://{"[" + host + "]" if ":" in host else host}:{port}'


def parser():
    p = argparse.ArgumentParser(description='Install a new ARGUS Server; without flags, ask for domain/IP and certificate setup.')
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
    p.add_argument('--console-port', type=int, default=9443)
    p.add_argument('--deploy-certificate', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--sync-certificate', action='store_true', help=argparse.SUPPRESS)
    return p


def configure(args, interactive):
    if not args.host and interactive:
        print('ARGUS Server 安装 / installation\n1. 域名 / domain (Let’s Encrypt)\n2. IP 地址 / IP address')
        choice = input('选择 / select [1/2]: ').strip()
        if choice not in ('1', '2'):
            raise InstallError('Select 1 or 2.')
        args.host = input('域名 / hostname: ' if choice == '1' else 'IP: ').strip()
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
        print('私有 IP 无法申请公开 CA 证书。可生成独立本地 CA；浏览器和 Agent 主机需安装其信任证书。')
        if input('生成本地 CA / create local CA? [y/N]: ').strip().lower() != 'y':
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
            print('需要公网 TCP 80 可达 / public TCP 80 must reach this host for issuance and renewal.')
            args.email = args.email or input('证书账户邮箱 / ACME email: ').strip()
            if not args.agree_tos:
                print('Let’s Encrypt subscriber terms: https://letsencrypt.org/repository/')
                args.agree_tos = input('同意服务条款 / agree to terms? [y/N]: ').strip().lower() == 'y'
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
        print(f'Downloading Linux {arch} Server bundle / 正在下载对应架构安装包…')
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
                sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', port))
            except OSError as exc:
                raise InstallError(f'Port {port} is unavailable; existing services were left running.') from exc


def preflight(args):
    if not path('/run/systemd/system').is_dir():
        raise InstallError('A running systemd host is required.')
    for tool in ('systemctl', 'systemd-sysusers', 'openssl'):
        if not shutil.which(tool):
            raise InstallError(f'Required command missing: {tool}')
    targets = ['/etc/argus-c2/server', '/etc/argus-c2/console', '/etc/argus-c2/setup',
               '/etc/argus-c2/server.json', '/etc/argus-c2/server-local.json', '/etc/argus-c2/console-install.json',
               '/var/lib/argus-c2-server', '/usr/local/libexec/argus-c2/server', '/usr/local/libexec/argus-c2/argus',
               '/usr/local/libexec/argus-c2/install-server.py', '/usr/local/share/argus-c2/agents',
               '/etc/sysusers.d/argus-c2-server.conf', '/etc/systemd/system/' + SERVICE,
               '/etc/systemd/system/' + SERVICE + '.d',
               '/etc/systemd/system/argus-console-renew.service', '/etc/systemd/system/argus-console-renew.timer']
    for target in targets:
        dest = path(target)
        trusted_parents(dest.parent)
        if os.path.lexists(dest):
            raise InstallError(f'Existing installation preserved: {dest}')
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
    print('Installing an isolated Certbot environment / 安装独立 Certbot 环境…')
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
               '--logs-dir', str(path('/var/log/argus-certbot')), '--cert-name', CERT_NAME, '--no-directory-hooks']
    if renew:
        return command + ['--deploy-hook', f'/usr/bin/python3 {path("/usr/local/libexec/argus-c2/install-server.py")} --deploy-certificate']
    command += ['--standalone', '--preferred-challenges', 'http', '--agree-tos', '--email', args.email]
    return command + (['--ip-address', args.host, '--required-profile', 'shortlived'] if args.address else ['--domain', args.host])


def certificates(args, stage):
    certdir = stage / 'console'
    certdir.mkdir(mode=0o700)
    cert, key = certdir / 'browser.pem', certdir / 'browser-key.pem'
    certbot = None
    if args.tls == 'letsencrypt':
        certbot = certbot_executable(args)
        for directory in ('/etc/argus-c2/acme', '/var/lib/argus-certbot', '/var/log/argus-certbot'):
            mkdir(path(directory), 0o700)
        print('Requesting a Let’s Encrypt certificate / 正在申请证书…')
        run(acme_arguments(args, certbot), timeout=300)
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
    run(['openssl', 'x509', '-in', cert, '-noout', '-checkip' if address else '-checkhost', host])


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
    run([server, 'console-bootstrap', 'issue', '-config', init / 'server.json', '-out', setup / 'bootstrap.token'])
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
    write_new(binaries / 'install-server.py', Path(__file__).read_bytes(), 0o644)
    sysusers = path('/etc/sysusers.d/argus-c2-server.conf')
    write_new(sysusers, 'u argus-server - "Argus diagnostics server" /var/lib/argus-c2-server /usr/sbin/nologin\n', 0o644)
    run(['systemd-sysusers', sysusers])
    account = pwd.getpwnam('argus-server')
    write_new(state / 'argus.db', (init / 'state/argus.db').read_bytes())
    os.chown(state / 'argus.db', account.pw_uid, account.pw_gid)
    os.chown(state, account.pw_uid, account.pw_gid)
    write_new(path('/etc/argus-c2/setup/bootstrap.token'), (setup / 'bootstrap.token').read_bytes())
    write_config(path('/etc/argus-c2/server.json'), args, state, True)
    write_config(path('/etc/argus-c2/server-local.json'), args, state)
    write_new(path('/etc/argus-c2/console-install.json'), json.dumps({'host': args.host, 'tls': args.tls}) + '\n')
    write_new(path('/etc/systemd/system/' + SERVICE), (bundle / SERVICE).read_bytes(), 0o644)
    flags = console_flags(args, console, artifacts, path('/run/credentials/' + SERVICE + '/console-key'))
    command = [str(binaries / 'server'), 'run', '-config', str(path('/etc/argus-c2/server.json')), *flags]
    # All generated arguments are canonical paths or validated DNS/IP/ports;
    # never interpolate caller-provided shell text into a systemd directive.
    dropin = '[Service]\nLoadCredential=console-key:' + str(console / 'browser-key.pem') + '\nExecStart=\nExecStart=' + ' '.join(command) + '\n'
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
    print(f'ARGUS Server installed / 安装完成\nConsole: {origin(args.host, args.console_port)}/setup\nFleet: {origin(args.host, args.fleet_port)}')
    print(f'Bootstrap secret (15 minutes; read locally): {path("/etc/argus-c2/setup/bootstrap.token")}')
    print('Configure Auth0/OIDC in /setup and bind the first administrator. Agent installers are already published.')
    if args.tls == 'local-ca':
        print(f'Install this Console CA into browser and Agent-host trust stores: {console / "ca.pem"}')
        print('Local certificates are not publicly trusted and are not ACME-renewed; replace the leaf before 90 days.')


def replace_file(dest, data, mode):
    fd, temporary = tempfile.mkstemp(prefix=dest.name + '.', dir=dest.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, dest)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


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


def main(argv=None):
    os.umask(0o077)
    # Root subprocesses use only system paths, not caller-controlled PATH entries.
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin'
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        raise InstallError('Run with sudo or as root.')
    arch = architecture()
    lockpath = path('/run/argus-c2-server-install.lock')
    fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w'):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallError('Another Server install or certificate deployment is running.') from exc
        if args.deploy_certificate or args.sync_certificate:
            deploy_certificate(require_hook=not args.sync_certificate)
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
    except (InstallError, OSError, ValueError, EOFError, KeyboardInterrupt, tarfile.TarError, subprocess.SubprocessError) as error:
        # Do not print raw HTTP/ACME exceptions, which can contain request URLs.
        print(str(error) if isinstance(error, InstallError) else f'Installation failed ({type(error).__name__}).', file=sys.stderr)
        print('Existing data was not reset. If files were installed, inspect journalctl -u argus-c2-server before manual recovery. ACME logs: /var/log/argus-certbot', file=sys.stderr)
        sys.exit(1)
