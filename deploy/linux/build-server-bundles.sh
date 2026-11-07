#!/bin/sh
# Build operator-published Server bundles. Nothing is installed on this host.
set -eu
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { printf '%s\n' 'usage: build-server-bundles.sh NEW_OUTPUT_DIRECTORY [RELEASE_TAG]' >&2; exit 1; }
release_tag=${2-}
python3 - "$release_tag" <<'PY'
import re, sys
if sys.argv[1] and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', sys.argv[1]):
    sys.exit('Invalid release tag.')
PY
[ ! -e "$1" ] && [ ! -L "$1" ] || { printf '%s\n' 'Output directory must be new.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output_dir=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$1")
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM
cd "$source_dir/web"
npm run build
cd "$source_dir"
sh deploy/linux/build-agent-artifacts.sh "$stage/agents"
mkdir "$stage/release"
for arch in amd64 arm64; do
    mkdir "$stage/$arch"
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -tags ui -o "$stage/$arch/server" ./cmd/server
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$stage/$arch/argus" ./cmd/argus
    cp "$stage/agents/agent-linux-amd64" "$stage/agents/agent-linux-arm64" deploy/linux/argus-c2-server.service "$stage/$arch/"
done
python3 - "$stage" <<'PY'
import hashlib, io, json, pathlib, sys, tarfile
stage = pathlib.Path(sys.argv[1])
for arch in ('amd64', 'arm64'):
    directory = stage / arch
    files = {p.name: p.read_bytes() for p in sorted(directory.iterdir())}
    manifest = {'format': 1, 'os': 'linux', 'arch': arch, 'files': {
        name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        for name, data in files.items()}}
    files['manifest.json'] = json.dumps(manifest, sort_keys=True).encode()
    with tarfile.open(stage / 'release' / f'argus-server-linux-{arch}.tar.gz', 'w:gz') as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            archive.addfile(info, io.BytesIO(data))
PY
python3 - "$stage/release/install-server.py" "$release_tag" <<'PY'
import json, pathlib, sys
source = pathlib.Path('deploy/linux/install-server.py').read_text()
marker = 'DEFAULT_RELEASE = None  # Replaced by the release builder to pin matching assets.'
if source.count(marker) != 1:
    sys.exit('Missing installer release marker.')
if sys.argv[2]:
    source = source.replace(marker, 'DEFAULT_RELEASE = ' + json.dumps(sys.argv[2]) + '  # Release-pinned assets.')
pathlib.Path(sys.argv[1]).write_text(source)
PY
mkdir -m 0755 -- "$output_dir"
cp "$stage/release/"* "$output_dir/"
cd "$output_dir"
sha256sum argus-server-linux-*.tar.gz install-server.py > SHA256SUMS
printf '%s\n' "Server bundles ready: $output_dir" 'Transfer this directory to a new Linux/systemd server, then run: sudo python3 install-server.py'
