#!/bin/sh
# ARGUS visible systemd installation; generated for one new, authorized host.
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'Run this installer with sudo or as root.'
[ "$(uname -s)" = Linux ] || fail 'This installer supports Linux only.'
case "$(uname -m)" in
    x86_64|amd64) arch=amd64; expected='{{AMD64_HASH}}' ;;
    aarch64|arm64) arch=arm64; expected='{{ARM64_HASH}}' ;;
    *) fail 'Supported architectures: x86_64 and arm64.' ;;
esac
[ -n "$expected" ] || fail 'No published Agent binary for this architecture.'
for tool in install systemctl systemd-sysusers runuser sha256sum mktemp date getent flock; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required command missing: $tool"
done
[ -d /run/systemd/system ] || fail 'A running systemd system is required.'
[ "$(date +%s)" -lt {{EXPIRES}} ] || fail 'Installation command expired; generate a new one.'
# Serialize installers before checking or writing any persistent Agent state.
[ ! -L /run/argus-c2-install.lock ] || fail 'Installer lock is a symlink.'
exec 9>/run/argus-c2-install.lock
flock -n 9 || fail 'Another Agent installer is running.'
for target in /etc/argus-c2/agent.json /etc/argus-c2/policy.json /etc/argus-c2/ca.pem /usr/local/libexec/argus-c2/agent /etc/systemd/system/argus-c2-agent.service /etc/sysusers.d/argus-c2-agent.conf; do
    [ ! -e "$target" ] && [ ! -L "$target" ] || fail 'An Agent installation already exists. Existing configuration and identity were preserved.'
done
[ ! -e /var/lib/argus-c2-agent ] && [ ! -L /var/lib/argus-c2-agent ] || fail 'Agent state already exists; refusing to overwrite its identity.'
! getent passwd argus-agent >/dev/null 2>&1 || fail 'The argus-agent account already exists; use the manual installation procedure.'
! getent group argus-agent >/dev/null 2>&1 || fail 'The argus-agent group already exists; use the manual installation procedure.'
if systemctl cat argus-c2-agent.service >/dev/null 2>&1; then fail 'An Agent unit already exists; use the manual installation procedure.'; fi
# Do not follow a pre-existing redirected installation directory.
for parent in /etc /etc/systemd /etc/systemd/system /etc/sysusers.d /usr /usr/local /usr/local/libexec /var /var/lib; do
    [ ! -L "$parent" ] || fail 'An installation parent is a symlink; use the manual procedure.'
done
for parent in /etc/argus-c2 /usr/local/libexec/argus-c2; do
    [ ! -L "$parent" ] || fail 'An installation directory is a symlink; use the manual procedure.'
done
stage=$(mktemp -d /var/tmp/argus-install.XXXXXXXX)
token_file=''
cleanup() {
    [ -z "$token_file" ] || rm -f -- "$token_file"
    rm -rf -- "$stage"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
artifact='{{ORIGIN}}/v1/console/install/assets/'"$arch/$expected"
if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --show-error --proto '=https' --tlsv1.3 --connect-timeout 10 --max-time 180 --max-filesize 67108864 --output "$stage/agent" "$artifact"
elif command -v wget >/dev/null 2>&1; then
    wget --quiet --https-only --max-redirect=0 --timeout=30 --tries=1 -O "$stage/agent" "$artifact"
else fail 'Install curl or GNU wget before running this command.'
fi
printf '%s  %s\n' "$expected" "$stage/agent" | sha256sum -c - >/dev/null || fail 'Agent download failed SHA-256 verification.'
[ "$(date +%s)" -lt {{EXPIRES}} ] || fail 'Installation command expired during download; generate a new one.'
cat > "$stage/agent.json" <<'ARGUS_AGENT_CONFIG'
{{AGENT_CONFIG}}
ARGUS_AGENT_CONFIG
cat > "$stage/policy.json" <<'ARGUS_AGENT_POLICY'
{{POLICY}}
ARGUS_AGENT_POLICY
cat > "$stage/ca.pem" <<'ARGUS_FLEET_CA'
{{FLEET_CA}}
ARGUS_FLEET_CA
cat > "$stage/argus-c2-agent.service" <<'ARGUS_SYSTEMD_UNIT'
{{UNIT}}
ARGUS_SYSTEMD_UNIT
printf '%s\n' 'u argus-agent - "Argus diagnostics agent" /var/lib/argus-c2-agent /usr/sbin/nologin' > "$stage/argus-c2-agent.conf"
install -d -m 0755 /etc/argus-c2 /usr/local/libexec/argus-c2 /etc/sysusers.d /etc/systemd/system
install -m 0755 "$stage/agent" /usr/local/libexec/argus-c2/agent
install -m 0644 "$stage/agent.json" /etc/argus-c2/agent.json
install -m 0644 "$stage/policy.json" /etc/argus-c2/policy.json
install -m 0644 "$stage/ca.pem" /etc/argus-c2/ca.pem
install -m 0644 "$stage/argus-c2-agent.conf" /etc/sysusers.d/argus-c2-agent.conf
systemd-sysusers /etc/sysusers.d/argus-c2-agent.conf
install -d -o argus-agent -g argus-agent -m 0700 /var/lib/argus-c2-agent
install -m 0644 "$stage/argus-c2-agent.service" /etc/systemd/system/argus-c2-agent.service
systemctl daemon-reload
token_file=/var/lib/argus-c2-agent/enroll.token
printf '%s\n' '{{TOKEN}}' > "$stage/enroll.token"
install -o argus-agent -g argus-agent -m 0600 "$stage/enroll.token" "$token_file"
runuser -u argus-agent -- /usr/local/libexec/argus-c2/agent run -config /etc/argus-c2/agent.json -check
[ "$(date +%s)" -lt {{EXPIRES}} ] || fail 'Installation command expired before enrollment. Use manual enrollment to finish this installation.'
runuser -u argus-agent -- /usr/local/libexec/argus-c2/agent enroll -config /etc/argus-c2/agent.json -token-file "$token_file"
rm -f -- "$token_file" "$stage/enroll.token"
token_file=''
systemctl enable --now argus-c2-agent.service
systemctl is-active --quiet argus-c2-agent.service || fail 'Agent was enrolled but the service did not start. Inspect journalctl -u argus-c2-agent.'
printf '%s\n' 'ARGUS Agent installed, enrolled and started as argus-agent.' 'Refresh the Agents page to check the first heartbeat.'
printf '%s\n' 'Console monitoring collects system information and metrics automatically; allow about one minute for the first measurements.' 'Uninstall or remove current Agent data and identity on THIS Agent host (confirmation required):'
cat <<'ARGUS_UNINSTALL'
( f=$(mktemp) || exit 1; trap 'rm -f -- "$f"' EXIT; curl --fail --location --proto '=https' --proto-redir '=https' https://github.com/Oreki0504/Argus-C2/releases/download/v0.1.0-preview.14/install-server.py -o "$f" && sudo python3 "$f" --uninstall agent --purge )
ARGUS_UNINSTALL
printf '%s\n' 'Omit --purge to keep Agent data for restoration; add --dry-run to preview removal.' 'Purge keeps historical backups. Delete or disable the Agent in Console Management when retiring it.'
