# Argus-C2 Phase 5: SSH Auditing and Service Status

Phase 5 adds two fixed read-only tasks to the Phase 4 dispatch and audit flow. `ssh.audit` accepts only `{"profile_id":"host"}`. `service.status` accepts only `{"service_id":"ssh"}`. Those IDs resolve through a policy installed by a local administrator on the probe. A task cannot supply a path, unit name, command, glob, user name, read limit, or baseline update.

The probe remains non-root. These collectors run natively on Linux; other operating systems return explicit `unsupported` observations. This remains a loopback-only development prototype. Administrator authentication and RBAC are Phase 6 work, and production installation hardening is Phase 7 work. No privileged helper is installed or implemented; see the [helper design and review gate](phase-5-helper-design.md).

## Enable resources locally

Follow the [Phase 4 guide](phase-4-implementation.md) to create development keys, enroll a probe, initialize its replay database, and start the server. The enrollment credentials, task-signing keys, replay state, and server state are reused. Phase 5 does not reset them or change their database schema versions.

Copy [task-policy-v2.json](../examples/task-policy-v2.json) to a locally administered policy path. The new permissions are both `false`, and both resource lists are empty. Existing version 1 policies retain their original serialization, digest, and authority; they cannot enable either new task. Every field in version 2 is required, including explicit false permissions and empty arrays.

For a development host with root-owned `/etc/ssh/sshd_config` and a canonical `sshd.service` unit, a complete policy could be:

```json
{
  "version": 2,
  "paused": false,
  "allow_system_info": true,
  "allow_system_metrics": true,
  "poll_seconds": 5,
  "timeout_seconds": 5,
  "max_per_minute": 30,
  "burst": 5,
  "max_result_bytes": 16384,
  "pending_bytes": 33554432,
  "telemetry": {
    "interval_seconds": 30,
    "sample_milliseconds": 1000,
    "disk_paths": ["/"],
    "network_interfaces": ["lo"]
  },
  "allow_ssh_audit": true,
  "allow_service_status": true,
  "ssh_profiles": [{
    "id": "host",
    "files": [{
      "id": "sshd_main",
      "kind": "sshd_config",
      "base_dir": "/etc/ssh",
      "relative_path": "sshd_config",
      "owner_uid": 0,
      "owner_gid": 0,
      "max_bytes": 65536,
      "baseline_sha256": ""
    }]
  }],
  "services": [{"id": "ssh", "unit": "sshd.service"}]
}
```

Review ownership and the canonical service name on the actual node before choosing these values. Some systems use `ssh.service`; aliases are deliberately rejected. Keep policy files, trust anchors, executables, and their parent directories under trusted local administration. Do not grant the probe root access or weaken existing SSH-file permissions to make an observation succeed.

To inspect a user's public authorization file, add an explicit `authorized_keys` mapping to a profile, with that file's expected numeric UID/GID. For example, use `base_dir: "/home/example/.ssh"` and `relative_path: "authorized_keys"` only when locally approved and readable by the probe. The probe does not enumerate home directories. An unreadable `.ssh` directory produces a coverage gap.

A profile has one to four files; there are at most four profiles and sixteen service mappings. IDs are 1–32 ASCII letters, digits, underscores, or hyphens and must begin with a letter or digit. Duplicate IDs and duplicate paths within a profile are rejected. `max_bytes` is 1,024–65,536 per file. Basenames are restricted to `authorized_keys`, `authorized_keys2`, `sshd_config`, or a `.conf` file beneath an explicitly named `sshd_config.d` component in `relative_path`. To select a drop-in, use a base such as `/etc/ssh` and a relative path such as `sshd_config.d/10-local.conf`.

Every mapping, permission, expected owner, limit, and baseline is included in the version 2 policy digest. Resource lists are sorted by their IDs for hashing, without changing collection order. Changing local policy invalidates previously queued tasks under the old digest. Wait for a fresh ready heartbeat before submitting new tasks. Already admitted work and cached results retain the Phase 4 behavior.

## Submit and inspect

Start the probe with the existing Phase 4 command, replacing `-policy` with the version 2 file. After its ready heartbeat, use the development-only local operator tool:

```text
go run ./cmd/localctl -state .local/phase4-server -action submit -agent-id REPLACE_WITH_AGENT_ID -type ssh.audit -profile-id host
go run ./cmd/localctl -state .local/phase4-server -action submit -agent-id REPLACE_WITH_AGENT_ID -type service.status -service-id ssh
go run ./cmd/localctl -state .local/phase4-server -action tasks
go run ./cmd/localctl -state .local/phase4-server -action audit
go run ./cmd/probectl -action audit -state .local/phase4-replay
```

`localctl` still requires direct access to the private server database. Its actor label is not authenticated administrator identity. The server does not know the probe's local mappings: a correctly formed but unmapped ID receives a durable `resource_denied` rejection from the probe. Disabled permissions receive `task_disabled`. Extra arguments, paths disguised as IDs, and malformed signed payloads are rejected before collection.

Both task types reuse signed original payload bytes, node/epoch binding, expiry, local rate limits, concurrency one, durable intent, cached duplicate results, and audit reservations. Successful reports must match the task's profile/service ID at both the probe and server. A report cannot be attached to a different resource merely by reusing its request ID. A successfully completed collector can report unavailable data; inspect the report's coverage or availability instead of treating task `succeeded` as a clean security finding.

## SSH observations and coverage

Each selected file reports its local file ID and kind, status, available numeric owner/group/mode/size, a SHA-256 digest when usable, baseline comparison, and bounded typed observations. Reports omit filesystem paths, complete public-key lines, key comments, option text, arbitrary configuration values, and file contents. Configuration observations contain only a small set of predefined directive/value pairs; key observations contain line number, key type, SHA-256 fingerprint, and whether options are present.

`sshd_config` parsing is deliberately limited to literal observations before the first `Match` line in each selected file. Supported observations are `PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication`, `KbdInteractiveAuthentication`, `PermitEmptyPasswords`, `StrictModes`, and `UsePAM`; `ChallengeResponseAuthentication` is normalized to `kbdinteractiveauthentication`. Duplicate directives retain the first observation and mark the file partial. Unsupported syntax or directives are not interpreted as effective settings.

The collector does not merge files, expand `Include`, evaluate `Match`, infer defaults, or run `sshd -T`. Explicitly mapped drop-ins are independent file observations, with no inference about whether or where sshd includes them. `Include`, `Match`, and dynamic authorization directives produce coverage findings. `AuthorizedKeysCommand` and other commands are never executed. This limitation matters because [OpenSSH configuration processing](https://man.openbsd.org/sshd_config) includes conditional settings and ordered include expansion.

Public-key parsing runs on each non-comment line so malformed lines cannot be silently skipped. Options and certificates yield fingerprints with a partial-coverage finding; their authorization semantics and certificate validity are not evaluated. Results contain at most eight key observations and eight directive observations per file. Files are limited to 512 lines and 8,192 bytes per line. Malformed input clears collected key/directive data for that file. Private-key markers cause `sensitive_content`, with no digest or key observations returned.

| Report field | Meaning |
| --- | --- |
| `coverage: complete` | All selected files were read and handled by this limited parser; not proof of effective sshd configuration or secure access |
| `coverage: partial` | At least one file yielded observations, with unsupported interpretation or other gaps |
| `coverage: unavailable` | No selected file yielded usable observations |
| `baseline: unconfigured` | No locally approved baseline was supplied |
| `baseline: match` / `changed` | Raw file bytes match / differ from the configured SHA-256 digest |
| `baseline: unavailable` | Reading or parsing did not produce a usable comparison |

A baseline is optional, installed manually in local policy after review. The probe never promotes observed content to a trusted baseline. Comments and whitespace changes also change the raw digest. Baseline drift and group/other-write permissions are separate findings and do not themselves mean parsing coverage is incomplete.

## File access boundary

Linux reads use descriptor-relative `openat2` constraints from a locally selected absolute base directory. Paths must be canonical, with no traversal, symlinks, magic links, or wildcard expansion. The configured base cannot be `/proc`, `/sys`, `/dev`, `/run`, or a descendant of those trees. Mounts may be crossed while establishing the explicit local base; traversal beneath that base rejects mount crossings. The [openat2 interface](https://man7.org/linux/man-pages/man2/openat2.2.html) supplies these resolution restrictions. Unsupported kernels fail closed without a weaker path-opening fallback.

Each checked directory must belong to root or the configured file owner, with no group/other writes. Root-owned sticky ancestors such as `/tmp` are permitted while establishing a private base; the configured base and relative directories do not get that exception. The final file must be regular, have one hard link, and match the exact configured UID/GID. Nonblocking open avoids waiting on a substituted FIFO. File metadata is checked before and after the bounded read, and the path is reopened to check inode identity. Observed replacement, in-place changes, or size instability discard the bytes.

Missing files, denied access, owner mismatch, unsafe paths/types, excessive size, unsupported facilities, and changed files have distinct status codes. Metadata is included only when safely available. These are point-in-time observations, not an atomic snapshot across the filesystem. A Go context cannot interrupt every blocked kernel filesystem call; use known local filesystems. No helper, shell, elevated process, permission modification, or automatic retry with more privilege is involved.

## Service status boundary

The collector connects only to `/run/dbus/system_bus_socket`; `DBUS_*` environment variables cannot redirect it. It checks the root-controlled socket directories and socket identity, uses explicit external authentication, resolves the systemd bus owner, and requires that unique owner to have UID 0. The bus daemon itself may use a dedicated unprivileged UID.

Queries address that verified unique owner, with D-Bus auto-start disabled. They call `Manager.GetUnit` and read only `Id`, `LoadState`, `ActiveState`, and `SubState` from the Unit interface. There is no service enumeration, `LoadUnit`, start, stop, restart, property mutation, or subprocess. As described by the [systemd D-Bus interface](https://github.com/systemd/systemd/blob/main/man/org.freedesktop.systemd1.xml), looking up an already loaded unit avoids the separate loading operation.

Each query has a two-second socket/context deadline, further bounded by the task deadline. Before the general D-Bus decoder receives input, a framing guard checks declared and nested lengths, sender, types, and padding. It permits only the scalar response forms needed by these queries, with at most 4 KiB each for headers/body, 8 KiB per frame, 64 KiB per connection, and 4 KiB of authentication input. Arbitrary arrays, nested variants, incoming calls, and file descriptors are rejected. No D-Bus file-descriptor passing is negotiated.

An available report contains the exact locally mapped unit name and its three states. A different canonical `Id` produces `alias_mismatch`. `unit_not_loaded` does not mean the service is stopped or absent on disk. `bus_unavailable`, `permission_denied`, `invalid_response`, and `unsupported` identify other gaps without fabricating state. The four property reads are sequential observations and may straddle a service transition.

## Validation and remaining scope

Tests cover signed malicious selectors, policy digest changes, version 1 compatibility, typed nested results, cross-resource result rejection over real mTLS, cached outcomes, audit compatibility, key redaction, baseline drift, malformed content, symlinks, hard links, FIFO/directory substitution, owner/permission failures, mount traversal, and deterministic file replacement/in-place changes. D-Bus framing tests exercise both byte orders, truncation, unexpected senders/types, and hostile inner lengths. CI requires a real read-only systemd query on Linux, including rejection of an unloaded unit and ignored bus-address environment variables.

Linux/Windows CI builds, vets, and runs the suite; Linux also runs the race detector, vulnerability scan, and bounded fuzzing of SSH parsing and D-Bus response framing alongside the existing protocol fuzzers. Schemas for [policy](../schemas/task-policy-v2.json), [SSH reports](../schemas/ssh-report-v1.json), and [service reports](../schemas/service-report-v1.json) describe the wire shapes; Go validation supplies the additional byte, consistency, and assignment checks.

Phase 5 does not add arbitrary file reads, log collection, effective SSH configuration evaluation, automatic baseline approval, service control, privileged helpers, administrator accounts, or public management listeners. Phase 6 adds authenticated administration and role enforcement to the existing narrow task model.
