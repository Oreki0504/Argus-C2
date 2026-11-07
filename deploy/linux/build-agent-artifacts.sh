#!/bin/sh
# Operator-selected artifacts for the Console one-command Linux installer.
set -eu
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: build-agent-artifacts.sh NEW_OUTPUT_DIRECTORY' >&2; exit 1; }
[ ! -e "$1" ] || { printf '%s\n' 'Output directory must be new.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -m 0755 -- "$1"
output_dir=$(CDPATH= cd -- "$1" && pwd)
cd "$source_dir"
for arch in amd64 arm64; do
    GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$output_dir/agent-linux-$arch" ./cmd/agent
done
printf '%s\n' 'Agent artifacts built. Configure -console-installer-dir and -console-fleet-origin when starting Console.'
