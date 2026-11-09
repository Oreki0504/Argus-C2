# Collectors and results

[Documentation](../README.md) · [Configuration](configuration.md) · [API](api.md)

There are six fixed Go collectors. Each requires a valid task type, permission in the local `allowed` list, and time and result-size limits. Service and SSH tasks also require local resource mappings. Network requests select a task type and mapping ID; they cannot supply commands, file paths, or new permissions.

## Execution outcome and data availability

`SUCCEEDED` means that the collector returned a valid report. It does not establish service health, file compliance, or complete coverage. For example, `service.status` may succeed with `available:false, code:"bus_unavailable"` when the system bus cannot be reached.

| Layer | Fields to inspect |
| --- | --- |
| Task execution | `task.status`, `result.status`, `result.error` |
| System and service data | Payload-level or per-metric `available` |
| SSH file observations | `coverage`, per-file `status`, `findings`, `baseline` |
| Process and socket lists | `available`, `truncated`, `items`, together with OS visibility restrictions |

Failed and unknown results have a `{}` payload and do not retain partial collection data. A valid report exceeding the local result limit becomes `FAILED/result_too_large`. Collection deadlines are at most 30 seconds, but Go contexts cannot forcibly terminate every blocked kernel I/O call; see [Security boundaries](security.md).

## system.info

Parameters are `{}`. Reads fixed `/proc` data, Linux `os-release`, and the hostname, returning:

| Field | Meaning |
| --- | --- |
| `available` | Whether hostname, kernel, and boot time were obtained |
| `os` | Recognized Linux distribution and numeric release, such as `Debian 13` or `Ubuntu 24.04`; falls back to `linux` if unavailable or unrecognized |
| `architecture` | Go architecture name, such as `amd64` or `arm64` |
| `hostname` / `kernel` | Hostname and kernel version |
| `boot_time` | Boot time as Unix seconds |

Distribution information comes from `ID` and `VERSION_ID` in `/etc/os-release`, falling back to `/usr/lib/os-release` if the first file cannot be read. Symlinks are resolved and reads are limited to 16 KiB; the file is never executed. Rolling distributions without a numeric release report just their name. Console Overview and node details use this value. Existing nodes need an updated Agent and a new `system.info` result (automatically scheduled hourly when Console is enabled, or dispatched by an administrator).

When unavailable, hostname and kernel are empty and boot time is 0; these zero values do not describe the host's actual state. Implementation: [system/linux.go](../internal/collectors/system/linux.go), [system/os_release_linux.go](../internal/collectors/system/os_release_linux.go).

## system.metrics

Parameters are `{}`; local `telemetry` configuration selects the resources. Metrics are returned as task results, not heartbeat payloads. When Console is enabled, the Server schedules fixed read-only collection tasks on idle Agent polls (metrics every 60 seconds, information every hour), subject to local policy.

| Field | Contents |
| --- | --- |
| `cpu` | `available`, `busy_percent`, `window_ms`; busy proportion between two `/proc/stat` samples |
| `memory` | `available`, `total_bytes`, `available_bytes` |
| `disks` | `path`, `available`, total and available bytes for each configured path |
| `networks` | `interface`, `available`, `rx_bytes`, `tx_bytes` for each configured interface |

Network counters are cumulative byte counts, not per-second rates. Disk collection uses `statfs` only for configured paths; it does not enumerate all mounts. Regressing CPU counters or an invalid sample window produce unavailable data. An empty `network_interfaces` list selects the lowest-metric default-route interface per address family, excluding loopback and deduplicating the selection. No usable route means no network counters. Explicit names override this selection.

## service.status

Parameters are `{"service_id":"journal"}`. The ID must map to an explicit `.service` unit. Queries use only `/run/dbus/system_bus_socket`, ignoring `DBUS_*` environment addresses. The collector does not execute `systemctl`, load missing units, or start services.

The report contains `service_id`, `observed_at`, `available`, `code`, `unit`, `load_state`, `active_state`, and `sub_state`. Inspect `active_state` only when the report is available.

| `code` | Meaning |
| --- | --- |
| Empty string | Allowed properties were obtained |
| `bus_unavailable` | The system bus could not be connected to or the required interaction could not complete |
| `permission_denied` | System-bus or service-identity permission checks failed |
| `unit_not_loaded` | The specified loaded unit was not found; no start is attempted |
| `alias_mismatch` | The returned unit identity differs from the local mapping |
| `invalid_response` | Response structure, size, or fields failed validation |
| `unsupported` | The platform does not support this collector implementation |

Bus queries also have an internal two-second timeout. Implementation: [services](../internal/collectors/services/).

## network.listeners

Parameters are `{}`. Reads the current network namespace's `/proc/net` tables in `tcp`, `tcp6`, `udp`, `udp6` order. It selects listening TCP sockets and unconnected UDP sockets, without network probes or scans of other machines.

The report is `{"available":true,"coverage":"complete","truncated":false,"items":[...]}`. Each item contains only `protocol`, `address`, and `port`, with no PID or socket owner. Output is limited to 256 items; each table has a 2 MiB read limit and an 8,192-line processing limit. Reaching the item or line limit marks the report truncated.

`coverage` is `complete`, `partial`, or `unavailable`. Missing tables, malformed skipped observations (including invalid state or address family), and read/Scanner failures produce partial coverage while retaining earlier valid entries and continuing with other tables. `available` means at least one table header was read; opening a table that immediately fails is insufficient. `truncated` indicates a byte, item, line-count, or 8,192-byte Scanner token bound. Ordinary I/O failures imply partial coverage without necessarily setting truncated. Context cancellation remains a task-level failure. Complete coverage applies only to these tables in the current namespace, never to every namespace or socket on the host. An empty partial list is not evidence of no listeners. Implementation: [network](../internal/collectors/network/).

## process.list

Parameters are `{}`. Enumerates visible `/proc` entries and reads process `status` files, returning at most 256 items after scanning at most 8,192 directory entries. Each file is limited to 16 KiB.

Items contain `pid`, `name`, a single-character `state`, and `uid`. The collector does not read command-line arguments, environment variables, open files, process memory, or executable contents. Processes that exit during collection, unreadable files, and parse failures are skipped without an itemized error list. Ordering and a complete, consistent process snapshot are not guaranteed.

`available` means directory entries were obtained or enumeration reached a clean empty end, not that every process was visible. `truncated` marks any known omission: item/scan limits, unreadable or vanished status files, malformed metadata, or interrupted directory reads. Valid earlier entries survive ordinary I/O errors; context cancellation remains a task failure. The existing protocol fields are retained, without a new process coverage field. The supplied agent systemd unit uses `ProtectProc=invisible`, typically limiting visibility to processes accessible to the service UID. Hidden entries cannot be counted, so even `truncated:false` does not promise host-wide completeness. Implementation: [process](../internal/collectors/process/).

## ssh.audit

Parameters are `{"profile_id":"host"}`, selecting up to four locally mapped files. The report contains `profile_id`, `observed_at`, `coverage`, and `files`.

Each file includes limited owner, mode, and size metadata, status, a content fingerprint, baseline comparison, selected directives or authorized public-key fingerprints, and findings. Raw configuration lines, public keys, comments, and private keys are not uploaded.

| Field | Meaning |
| --- | --- |
| `coverage` | `complete`, `partial`, or `unavailable`, scoped only to these bounded file observations |
| `metadata_available` / `metadata` | Availability of UID, GID, mode bits, and file size |
| `sha256` | Fingerprint of permitted, successfully parsed data; empty for unreadable or sensitive content |
| `baseline` | `unconfigured`, `match`, `changed`, or `unavailable` |
| `keys` | Bounded line numbers, public-key types, SHA-256 key fingerprints, and presence of options |
| `directives` | Line numbers, names, and bounded values of selected SSH directives |
| `findings` | Observations about permissions, unevaluated syntax, baseline changes, and limits |

SSHD observations cover only supported simple literal directives, including `PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication`, `KbdInteractiveAuthentication`, `PermitEmptyPasswords`, `StrictModes`, and `UsePAM`. They do not expand `Include`, evaluate `Match`, execute dynamic key commands, or compute the effective configuration. `complete` does not mean SSH is secure or all configuration has been audited.

Content is limited to 64 KiB, further restricted by local `max_bytes`; parsing allows at most 512 lines and 8,192 bytes per line. Each file has at most eight key observations, eight directive observations, and sixteen findings. Private-key markers, invalid encoding, or control characters prevent content summaries. Baselines are compared, never updated automatically.

Linux file access uses `openat2` and constrained directory descriptors. It rejects symbolic and hard links, special files, path escapes, mount crossings within the configured base, unexpected UID/GID, replaceable directories, and changes during reading. Root-owned sticky ancestor directories have an explicit exception. The agent still needs actual read permissions. `ProtectHome=true` hides authorized-key files under user home directories; adding a profile does not bypass it.

Common file statuses include `missing`, `permission_denied`, `unsafe_path`, `unsafe_type`, `owner_mismatch`, `too_large`, `changed_during_read`, `unsupported`, `parse_error`, and `sensitive_content`. Implementations: [ssh](../internal/collectors/ssh/), [saferead](../internal/saferead/). Field validation: [inspection.go](../internal/protocol/inspection.go).
