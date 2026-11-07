# Linux deployment

[Documentation](../README.md) · [Quick start](quickstart.md) · [Configuration](configuration.md) · [Operations](operations.md)

This guide installs one server and one or more agents on explicitly authorized Linux hosts. Hosts need systemd, systemd-sysusers, and support for `LoadCredential`. Native deployment CI targets Ubuntu 24.04; check unit-option support on other distributions. Restricted SSH file reading requires Linux `openat2`.

The management host needs one configured HTTPS port. Agents need only outbound access to it. The server certificate must include the DNS name or IP address clients use. Synchronize host clocks because certificate and task validity depend on time.

## 1. Build and install

Build the three programs for the target architecture from the repository root:

```sh
mkdir -p bin
for command in server agent argus; do
  CGO_ENABLED=0 go build -trimpath -o "bin/$command" "./cmd/$command"
done
sudo sh deploy/linux/install.sh "$PWD/bin"
```

The installer copies programs to `/usr/local/libexec/argus-c2/`, installs two units and a sysusers definition, creates `argus-server` / `argus-agent` accounts with separate mode-0700 state directories, and runs daemon-reload. It does not initialize the server, enroll nodes, generate runtime configuration, or enable services.

Rerunning the installer replaces programs and units. Stop running test services and retain their binaries and state before doing so; installation does not rewrite configuration or databases.

| Path | Purpose and ownership |
| --- | --- |
| `/usr/local/libexec/argus-c2/{server,agent,argus}` | Root-managed executables |
| `/etc/argus-c2/server.json` | Root-managed server runtime configuration |
| `/etc/argus-c2/server/` | CA, server certificate, private keys, administrator configuration |
| `/etc/argus-c2/agent.json`, `policy.json`, `ca.pem` | Root-managed configuration and trust anchor readable by the agent |
| `/var/lib/argus-c2-server/` | Server database owned by `argus-server` |
| `/var/lib/argus-c2-agent/` | Node certificate, key, and deduplication state owned by `argus-agent` |

Start only the required component on each host. A management workstation can run the built `argus` binary directly without installing an agent service.

## 2. Initialize the management server

Run these commands on the management host, assuming `/etc/argus-c2/server` does not exist. Replace `fleet.example.com` with the actual reachable name, without a scheme or port:

```sh
sudo /usr/local/libexec/argus-c2/server init \
  -dir /etc/argus-c2/server \
  -hosts fleet.example.com \
  -listen 0.0.0.0:8443

sudo install -o argus-server -g argus-server -m 0600 \
  /etc/argus-c2/server/state/argus.db \
  /var/lib/argus-c2-server/argus.db
sudo chmod 0755 /etc/argus-c2/server
sudo chmod 0644 /etc/argus-c2/server/ca.pem /etc/argus-c2/server/server.pem
```

This copies a newly initialized, closed database. Do not copy a live database this way; see [Operations](operations.md) for online backup. `/etc/argus-c2/server/state` and the generated `server/server.json` are bootstrap artifacts. The service uses the top-level configuration below and state under `/var/lib`; do not start a second server using the bootstrap configuration. After checking the service setup, the bootstrap state can be moved into a private archive.

Create `/etc/argus-c2/server.json`:

```sh
sudo tee /etc/argus-c2/server.json >/dev/null <<'JSON'
{
  "listen": "0.0.0.0:8443",
  "state_dir": "/var/lib/argus-c2-server",
  "certificate": "/etc/argus-c2/server/server.pem",
  "private_key": "/run/credentials/argus-c2-server.service/server-key",
  "ca": "/etc/argus-c2/server/ca.pem",
  "issuer_key": "/run/credentials/argus-c2-server.service/issuer-key",
  "admins": "/run/credentials/argus-c2-server.service/admins"
}
JSON
sudo chown root:root /etc/argus-c2/server.json
sudo chmod 0644 /etc/argus-c2/server.json
sudo chmod 0600 /etc/argus-c2/server/server-key.pem \
  /etc/argus-c2/server/ca-key.pem /etc/argus-c2/server/admins.json \
  /etc/argus-c2/server/admin.token
```

The [server unit](../deploy/linux/argus-c2-server.service) supplies three secret files through `LoadCredential`; source private-key permissions can remain restricted. `/run/credentials/...` paths belong to the service runtime context and may be inaccessible to `run -check` from an ordinary terminal. For pre-start credential checks, use a separate private configuration referencing the three source files and run the check as root. Keep the service configuration pointing to its runtime credentials.

```sh
sudo systemctl enable --now argus-c2-server
sudo systemctl status argus-c2-server --no-pager
sudo journalctl -u argus-c2-server -n 50 --no-pager
```

## 3. Configure a management workstation

Transfer `ca.pem` and the initial `admin.token` through an authenticated channel to a private workstation directory, such as `/private/argus/`. Keep the token mode 0600 and its directory mode 0700. Agents do not need the CA private key, and an administrator token is not an enrollment token.

Define this function in the administrator's terminal, adjusting paths as needed:

```sh
argus_admin() {
  /usr/local/libexec/argus-c2/argus \
    -server https://fleet.example.com:8443 \
    -ca /private/argus/ca.pem \
    -token-file /private/argus/admin.token "$@"
}
argus_admin health
argus_admin nodes
```

Use the initial account to establish administration. Generate individual tokens for routine use as described in [Operations](operations.md).

## 4. Configure and enroll a node

For a **new Agent-only host**, an initialized Web Console can generate a single curl/wget installation command from Management → Agents → Add agent. It installs only the Agent and registers it automatically. See [one-command installation](agent-installation.zh-CN.md) for artifact publication, TLS prerequisites and failure recovery. The manual procedure below remains available for existing installations and custom local policies.

Install the same programs and units on the node. Transfer the trusted `ca.pem` and install it as `/etc/argus-c2/ca.pem`, owned by root with mode 0644. Use [examples/agent.json](../examples/agent.json) for `/etc/argus-c2/agent.json`, changing `server` to the actual HTTPS origin. Copy [examples/policy.json](../examples/policy.json) to `/etc/argus-c2/policy.json`. Both JSON files should be root-owned, mode 0644, with a parent directory the agent cannot write.

```sh
sudo chown root:root /etc/argus-c2/agent.json /etc/argus-c2/policy.json /etc/argus-c2/ca.pem
sudo chmod 0644 /etc/argus-c2/agent.json /etc/argus-c2/policy.json /etc/argus-c2/ca.pem
sudo -u argus-agent /usr/local/libexec/argus-c2/agent run \
  -config /etc/argus-c2/agent.json -check
```

On the management workstation, create a short-lived token for this node:

```sh
argus_admin enrollment-token -ttl 300 -out /private/argus/node-enroll.token
```

Before it expires, transfer the token through an authenticated channel to `/var/lib/argus-c2-agent/enroll.token` on the node, owned by `argus-agent:argus-agent` with mode 0600. Issue a separate token for each node.

Run on the node:

```sh
sudo chown argus-agent:argus-agent /var/lib/argus-c2-agent/enroll.token
sudo chmod 0600 /var/lib/argus-c2-agent/enroll.token
sudo -u argus-agent /usr/local/libexec/argus-c2/agent enroll \
  -config /etc/argus-c2/agent.json \
  -token-file /var/lib/argus-c2-agent/enroll.token
sudo rm /var/lib/argus-c2-agent/enroll.token
sudo systemctl enable --now argus-c2-agent
sudo systemctl status argus-c2-agent --no-pager
```

After successful enrollment, the workstation's enrollment-token copy is no longer needed either. Preserve the agent certificate, key, and database in its state directory; do not overwrite them with root-owned empty state.

## 5. Verify each node

List nodes from the management workstation and use the actual node ID:

```sh
argus_admin nodes
argus_admin create -node NODE_ID -type system.info
argus_admin create -node NODE_ID -type system.metrics
argus_admin wait -task TASK_ID -timeout 2m
```

Save each returned task ID and inspect its report. Check that `last_seen_at` advances, results belong to the intended node, and payload data is available. For `service.status`, add both the task name and a service mapping to local policy, restart the agent, then run `create -type service.status -resource journal`. Service collection is disabled in the default policy.

Node administrators should add SSH profiles or broaden process visibility only as required by their diagnostics. Default `ProtectHome=true` and `ProtectProc=invisible` restrict visibility; a policy entry alone does not grant OS access.

## Service limits and acceptance scope

| Setting | Server | Agent |
| --- | --- | --- |
| User | `argus-server` | `argus-agent` |
| Writable persistent directory | `/var/lib/argus-c2-server` | `/var/lib/argus-c2-agent` |
| `MemoryMax` | 256 MiB | 192 MiB |
| `TasksMax` | 128 | 64 |
| `CPUQuota` | Not set in the unit | 50% |
| Restart | `on-failure`, ten-second delay | `on-failure`, ten-second delay |

Both units enable `NoNewPrivileges`, empty capability sets, `ProtectSystem=strict`, private temporary directories, and syscall/address-family restrictions. The [server unit](../deploy/linux/argus-c2-server.service) and [agent unit](../deploy/linux/argus-c2-agent.service) are authoritative for the exact settings.

The native systemd CI script writes system directories and is intended only for an explicitly disposable GitHub Actions VM. It is not a health-check command for an existing host. Sustained acceptance on five independent VPS instances still requires host-level records; these installation instructions do not establish that those deployments have occurred.
