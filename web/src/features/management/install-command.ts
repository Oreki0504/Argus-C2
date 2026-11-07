// Download completely before executing: failed/truncated transfers never run.
// The URL is a credential; callers must keep it only in dialog memory.
export function installCommand(url: string, tool: 'curl' | 'wget') {
  const quoted = `'${url.replaceAll("'", "'\"'\"'")}'`
  const download =
    tool === 'curl'
      ? `curl --fail --silent --show-error --proto '=https' --tlsv1.3 --connect-timeout 10 --max-time 30 --output "$f" ${quoted}`
      : `wget --quiet --https-only --max-redirect=0 --timeout=30 --tries=1 -O "$f" ${quoted}`
  return `( umask 077; f=$(mktemp /tmp/argus-install.XXXXXXXX) || exit 1; trap 'rm -f -- "$f"' EXIT; trap 'exit 1' HUP INT TERM; ${download} && { if [ "$(id -u)" -eq 0 ]; then sh "$f"; else sudo sh "$f"; fi; } )`
}
