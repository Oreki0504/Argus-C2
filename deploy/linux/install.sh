#!/bin/sh
# Install binaries and service definitions; enrollment and service startup are explicit.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "Run installation as root" >&2; exit 1; fi
if [ "$#" -ne 1 ]; then echo "usage: install.sh /absolute/path/to/bin" >&2; exit 1; fi
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -m 0755 /usr/local/libexec/argus-c2 /etc/argus-c2 /etc/sysusers.d
for binary in server agent argus; do
    install -m 0755 "$1/$binary" "/usr/local/libexec/argus-c2/$binary"
done
install -m 0644 "$source_dir/argus-c2.sysusers.conf" /etc/sysusers.d/argus-c2.conf
systemd-sysusers /etc/sysusers.d/argus-c2.conf
install -d -o argus-server -g argus-server -m 0700 /var/lib/argus-c2-server
install -d -o argus-agent -g argus-agent -m 0700 /var/lib/argus-c2-agent
install -m 0644 "$source_dir/argus-c2-server.service" /etc/systemd/system/argus-c2-server.service
install -m 0644 "$source_dir/argus-c2-agent.service" /etc/systemd/system/argus-c2-agent.service
systemctl daemon-reload
printf '%s\n' 'Installed. Configure and enroll using docs/operations.md before starting services.'
