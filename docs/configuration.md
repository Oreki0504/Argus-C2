# Configuration reference

[Documentation](../README.md) · [简体中文](configuration.zh-CN.md) · [Collectors](collectors.md) · [Deployment](deployment.md)

Configuration comes from local files, not the management API. The server and agent load their configuration once at startup; restart the relevant process after changing accounts, policy, or connection settings. JSON does not accept comments, unknown fields, duplicate keys, `null`, or trailing content. Supply all required fields shown below; use `[]` for empty collections.

File and directory paths inside configuration must be canonical absolute paths. The loader does not expand `~`, environment variables, or templates. Configuration files must be regular files, not symbolic links. Keep private keys, administrator configuration, and tokens mode 0600, and state directories mode 0700. Locally trusted administrators should control configuration, CA files, and policy. Restricted systemd credential ACLs are also supported by the secret-file reader.

## Server configuration

```json
{
  "listen": "127.0.0.1:8443",
  "state_dir": "/var/lib/argus-c2-server",
  "certificate": "/etc/argus-c2/server/server.pem",
  "private_key": "/etc/argus-c2/server/server-key.pem",
  "ca": "/etc/argus-c2/server/ca.pem",
  "issuer_key": "/etc/argus-c2/server/ca-key.pem",
  "admins": "/etc/argus-c2/server/admins.json"
}
```

| Field | Meaning |
| --- | --- |
| `listen` | `host:port`; controls binding, not certificate SANs |
| `state_dir` | Initialized state directory containing `argus.db` |
| `certificate` / `private_key` | Matching server TLS certificate and private key |
| `ca` | Current single enrollment CA certificate, also used to trust TLS clients |
| `issuer_key` | ECDSA private key matching the enrollment CA |
| `admins` | Named administrator token-digest configuration |

The file is limited to 8 KiB. Startup checks the server certificate's purpose, chain, and validity. The supplied systemd unit delivers three secret files using `LoadCredential`; use the paths in [Deployment](deployment.md) instead of making the source keys broadly readable.

History retention has no JSON field or automatic schedule: use the local `server prune` command, defaulting to a 30-day preview. See [Operations](operations.md#server-history-retention). The current `ca`/`issuer_key` pair is an online root; the [intermediate design](security.md#offline-root-and-online-intermediate-plan) is not a supported configuration yet.

## Administrator configuration

The shape is `{"users":[account records]}`. Generate records with the command below instead of substituting the digest of an ordinary password:

```sh
bin/argus new-user -name observer -role ReadOnly -out /private/observer.token
```

The complete stdout object contains `name`, `role`, and `token_sha256`. Add it to the `users` array in `admins.json`, then restart the server. Only `Admin` and `ReadOnly` are supported. Keeping at least one usable Admin is an operational responsibility; the validator does not enforce that condition.

There must be 1–100 accounts. Names contain 1–64 ASCII letters, digits, `_`, or `-`. Names and token digests must be unique. Digests are 64 lowercase hexadecimal SHA-256 characters. The whole file is limited to 32 KiB. There is no password login, session store, automatic account expiry, or remote user-management API.

## Agent configuration

Start with [examples/agent.json](../examples/agent.json):

```json
{
  "server": "https://fleet.example.com:8443",
  "ca": "/etc/argus-c2/ca.pem",
  "state_dir": "/var/lib/argus-c2-agent",
  "policy": "/etc/argus-c2/policy.json"
}
```

| Field | Meaning |
| --- | --- |
| `server` | HTTPS origin; its hostname/IP must match the server certificate |
| `ca` | Locally trusted CA; no verification bypass or trust-on-first-use option |
| `state_dir` | Initialized during enrollment and preserved for subsequent runs |
| `policy` | Local policy file, also validated during enrollment |

The file is limited to 8 KiB. State includes `agent-key.pem`, `agent.pem`, `probe.db`, and `probe.lock`. The `probe` filenames are internal naming; the program and documentation call the node component an agent.

## Local policy

[examples/policy.json](../examples/policy.json) is a complete minimal policy:

```json
{
  "allowed": ["system.info", "system.metrics"],
  "poll_seconds": 10,
  "timeout_seconds": 10,
  "max_result_bytes": 65536,
  "telemetry": {
    "sample_milliseconds": 1000,
    "disk_paths": ["/"],
    "network_interfaces": []
  },
  "services": [],
  "ssh_profiles": []
}
```

These are example values, not implicit defaults for omitted fields.

| Field | Accepted range and behavior |
| --- | --- |
| `allowed` | 0–6 implemented task names, no duplicates; `[]` denies collection while heartbeat, renewal, and other cycle operations continue |
| `poll_seconds` | 5–60 seconds after a normal cycle, plus less than one second of jitter |
| `timeout_seconds` | 1–30 seconds; collection also uses the smaller task execution budget, starting after authorization and durable RUNNING |
| `max_result_bytes` | 1024–65536 bytes for the complete serialized result |
| `telemetry.sample_milliseconds` | 100–5000 milliseconds between CPU samples; leave enough execution budget |
| `telemetry.disk_paths` | 0–8 unique canonical absolute Linux paths, up to 256 bytes each |
| `telemetry.network_interfaces` | 0–16 unique interface names, 1–15 bytes each; no `/`, `:`, or spaces |
| `services` | 0–16 service mappings with unique IDs |
| `ssh_profiles` | 0–4 profiles with unique IDs; 1–4 files per profile |

The policy is limited to 32 KiB. `telemetry` is used by `system.metrics`; there is no `interval_seconds` field or periodic metrics upload.

### Enable additional collectors

This is a complete policy example. Adjust SSH paths and UID/GID expectations to the actual node:

```json
{
  "allowed": ["system.info", "system.metrics", "service.status", "network.listeners", "process.list", "ssh.audit"],
  "poll_seconds": 10,
  "timeout_seconds": 10,
  "max_result_bytes": 65536,
  "telemetry": {
    "sample_milliseconds": 1000,
    "disk_paths": ["/"],
    "network_interfaces": []
  },
  "services": [
    {"id": "journal", "unit": "systemd-journald.service"}
  ],
  "ssh_profiles": [
    {
      "id": "host",
      "files": [
        {
          "id": "config",
          "kind": "sshd_config",
          "base_dir": "/etc/ssh",
          "relative_path": "sshd_config",
          "owner_uid": 0,
          "owner_gid": 0,
          "max_bytes": 16384,
          "baseline_sha256": ""
        }
      ]
    }
  ]
}
```

Mapping IDs contain 1–32 ASCII letters, digits, `_`, or `-`, beginning with a letter or digit. A service `unit` must be an explicit `.service` name of at most 128 bytes. Wildcards, `..`, and empty templates such as `name@.service` are rejected. Collection only reads already loaded units and never starts them.

SSH `kind` accepts only `sshd_config` or `authorized_keys`. `base_dir` must be a canonical absolute path outside `/proc`, `/sys`, `/dev`, `/run`, and their descendants. `relative_path` must stay under that directory, without absolute paths, parent traversal, or wildcards. Supported filenames are `sshd_config`, `.conf` files under `sshd_config.d/`, and `authorized_keys` / `authorized_keys2`.

`owner_uid` and `owner_gid` must match the file. `max_bytes` is 1024–65536. `baseline_sha256` is either `""` or an independently established 64-character lowercase digest; it is compared but never learned or updated automatically. A policy grant does not override OS permissions, including systemd home-directory restrictions.

## What configuration checks establish

```sh
bin/server run -config /absolute/server.json -check
bin/agent run -config /absolute/agent.json -check
```

The server opens its existing database and loads accounts and credentials, but does not bind a port or test remote access. The agent checks configuration and policy without opening identity state, connecting to the server, or probing mapped resources. Neither command is an end-to-end acceptance test. Running processes do not reload changed configuration.

Implementation references: [config](../internal/config/config.go), [policy](../internal/policy/policy.go), [resource mappings](../internal/resources/resources.go), and [administrator authentication](../internal/auth/auth.go).
