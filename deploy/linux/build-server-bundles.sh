#!/bin/sh
# Build operator-published Server bundles. Nothing is installed on this host.
set -eu
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: build-server-bundles.sh NEW_OUTPUT_DIRECTORY' >&2; exit 1; }
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
cp deploy/linux/install-server.py "$stage/release/"
mkdir -m 0755 -- "$output_dir"
cp "$stage/release/"* "$output_dir/"
cd "$output_dir"
sha256sum argus-server-linux-*.tar.gz install-server.py > SHA256SUMS
printf '%s\n' "Server bundles ready: $output_dir" 'Transfer this directory to a new Linux/systemd server, then run: sudo python3 install-server.py'
