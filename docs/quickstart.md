# Local quick start

[Documentation](../README.md) · [简体中文](quickstart.zh-CN.md) · [CLI reference](cli.md) · [Linux deployment](deployment.md)

This guide runs the server, agent, and CLI on one Linux machine. It stores everything in a private temporary directory and installs no system services. Run the blocks in order in the same Bash terminal, as a **non-root user**. You need Go 1.27.3, Python 3, and an available local TCP port 8443.

For the Web Console, use the [Server installer](server-installation.zh-CN.md). Its random administrator token opens management immediately; OAuth linking is optional afterward. The CLI demo below uses a separate Fleet admin.token, which cannot authenticate in the browser.

The same installer handles updates (`--update server|agent`) and [uninstall](server-installation.zh-CN.md#卸载-server-或-agent) (`--uninstall server|agent`). Uninstall preserves data by default; add `--purge` explicitly to remove current component data and its dedicated account. Historical backups remain.

## 1. Build

From the repository root:

```bash
mkdir -p bin
for command in server agent argus; do
  CGO_ENABLED=0 go build -trimpath -o "bin/$command" "./cmd/$command"
done
```

## 2. Initialize and start the server

`server init` requires a directory that does not already exist. It creates the CA, server certificate, administrator token, configuration, and database. It does not print private keys or tokens.

```bash
umask 077
export ARGUS_DEMO
ARGUS_DEMO=$(mktemp -d /tmp/argus-demo.XXXXXX)
printf 'Demo directory: %s\n' "$ARGUS_DEMO"

bin/server init -dir "$ARGUS_DEMO/server" \
  -hosts localhost,127.0.0.1 -listen 127.0.0.1:8443
bin/server run -config "$ARGUS_DEMO/server/server.json" -check
bin/server run -config "$ARGUS_DEMO/server/server.json" \
  >"$ARGUS_DEMO/server.log" 2>&1 &
ARGUS_SERVER_PID=$!
ARGUS_AGENT_PID=
trap 'kill "$ARGUS_SERVER_PID" ${ARGUS_AGENT_PID:+"$ARGUS_AGENT_PID"} 2>/dev/null || true' EXIT

argus_demo() {
  bin/argus -server https://localhost:8443 \
    -ca "$ARGUS_DEMO/server/ca.pem" \
    -token-file "$ARGUS_DEMO/server/admin.token" "$@"
}

for attempt in {1..50}; do
  if argus_demo health >/dev/null 2>&1; then break; fi
  sleep 0.1
done
argus_demo health
```

The last command should return `{"status":"ok"}`. If it fails, inspect `server.log` in the demo directory before continuing. `-hosts` defines the DNS names and IP addresses in the certificate; `-listen` defines the network binding.

## 3. Configure and enroll an agent

The example policy enables only `system.info` and `system.metrics`. Configuration paths must be absolute. Required fields are not filled in automatically when omitted.

```bash
cp examples/policy.json "$ARGUS_DEMO/policy.json"
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path(os.environ["ARGUS_DEMO"])
config = {
    "server": "https://localhost:8443",
    "ca": str(root / "server/ca.pem"),
    "state_dir": str(root / "agent"),
    "policy": str(root / "policy.json")
}
(root / "agent.json").write_text(json.dumps(config, indent=2) + "\n")
PY

bin/agent run -config "$ARGUS_DEMO/agent.json" -check
argus_demo enrollment-token -out "$ARGUS_DEMO/enroll.token" -ttl 300
bin/agent enroll -config "$ARGUS_DEMO/agent.json" \
  -token-file "$ARGUS_DEMO/enroll.token"
rm "$ARGUS_DEMO/enroll.token"

bin/agent run -config "$ARGUS_DEMO/agent.json" \
  >"$ARGUS_DEMO/agent.log" 2>&1 &
ARGUS_AGENT_PID=$!
argus_demo nodes
```

An enrollment token is distinct from an administrator token. It assigns one node identity; retries can recover that identity only before token expiry and with the same public key. The agent generates `agent-key.pem` locally.

`agent run -check` validates configuration and policy only. Starting the agent checks the actual certificate and state and attempts network communication. Passing `-check` does not establish successful enrollment.

## 4. Submit tasks and retrieve results

This demo has one node, so the following commands select the first list entry. In a fleet, select the intended node explicitly.

```bash
ARGUS_NODE_ID=$(argus_demo nodes | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
ARGUS_TASK_ID=$(argus_demo create -node "$ARGUS_NODE_ID" -type system.info \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
argus_demo wait -task "$ARGUS_TASK_ID" -timeout 1m

ARGUS_METRICS_ID=$(argus_demo create -node "$ARGUS_NODE_ID" -type system.metrics \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
argus_demo wait -task "$ARGUS_METRICS_ID" -timeout 1m
argus_demo audit
```

The response contains `task` and, once a result has been stored, `result`. Inspect the task status first, then data availability in `result.payload`. `wait` exits successfully for `SUCCEEDED`; `FAILED`, `UNKNOWN`, and a wait timeout produce a nonzero exit.

By default, the agent waits about ten seconds after each cycle, so execution is not immediate. `wait -timeout` controls how long the CLI waits; `create -ttl` controls the deadline for first execution authorization. `create -execution-timeout 10s` supplies a separate collection budget, capped by agent policy.

## 5. Stop the demo

```bash
kill "$ARGUS_AGENT_PID" "$ARGUS_SERVER_PID"
wait "$ARGUS_AGENT_PID" "$ARGUS_SERVER_PID"
trap - EXIT
printf 'State and logs retained in: %s\n' "$ARGUS_DEMO"
```

The data directory remains available, and both programs can restart with the same configuration. Do not initialize the existing server directory again or delete an enrolled agent's `probe.db` to reset it. Once the processes have stopped, you may remove the temporary directory if the demo is no longer needed.

For service, SSH, process, or socket diagnostics, continue with [Configuration](configuration.md) and [Collectors](collectors.md). For a persistent test deployment, follow [Linux deployment](deployment.md) to use separate accounts and administrator-controlled policy files.
