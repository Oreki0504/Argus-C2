**Argus-C2: Phase 1 Architecture and Security Design**

Status: design proposal; this phase contains no implementation code. Target environment: explicitly enrolled Linux VPS nodes owned and administered by the operator. Initial design: 2026-09-16. Naming, terminology, and English documentation update: 2026-09-22.

Argus-C2 is a self-hosted remote administration and incident-response control plane. This document calls the resident VPS client a probe; `agent` in package names, protocol fields, and API paths refers to that same node client. Systemd hardening and filesystem restrictions describe the deployment controls applied to this Linux service.

This phase defines the threat model, architecture, trust boundaries, Go package layout, protocol, security invariants, MVP scope, and excluded capabilities. The core objective is that an attacker who compromises the central server and its online keys can request only the limited operations independently allowed on each node, without acquiring arbitrary command execution or arbitrary filesystem write primitives through the protocol.

This containment objective depends on explicit assumptions. A compromised server may still obtain approved telemetry, falsify the central view, suppress scheduling, or exhaust bounded resources. If service restarts are enabled later, it may disrupt allowlisted services. Vulnerabilities in a probe, privileged helper, or operating system may also break the boundary.

**1. Threat model and security assumptions**

Protected assets include node execution privileges and filesystem integrity, SSH authorization configuration, node identity keys, administrator credentials, task authenticity, telemetry confidentiality, and audit evidence.

| Threat or attacker capability | Primary controls | Remaining limitations |
| --- | --- | --- |
| Internet attacker intercepting, modifying, or impersonating traffic | Mutually verified TLS, individual node certificates, explicit enrollment, signed tasks | Network blocking can still take nodes offline |
| Stolen administrator password or session | Strong password hashing, rate limits, session revocation, optional MFA, RBAC | A stolen Admin session can request locally allowed tasks |
| Full central-server compromise, including its database and online signing keys | Probe-local policy, static task registry, non-root identity, no generic execution or write interface | Disclosure of approved data, falsified server records, task flooding, and availability impact |
| Compromise of one probe or its identity key | Per-node identity, certificate-bound authorization on every interface, node-scoped access, certificate revocation | That node's reports become untrusted and cannot serve as evidence about other nodes |
| An unprivileged node user manipulating logs, paths, or symlinks | Fixed resource mappings, safe file opening, strict parsing, bounded output | Source data writable by that user may be false |
| Replay, duplicate delivery, reconnects, or crashes during execution | Expiration, persistent deduplication, identity binding, explicit indeterminate outcomes | No claim of exactly-once execution for arbitrary side effects |
| Oversized payloads, slow connections, task flooding, or storage exhaustion | Independent server and probe quotas, deadlines, backpressure, audit-capacity alerts | Quotas bound damage but do not guarantee continuous availability |
| Audit-record modification or deletion | Independent records at both ends, hash chains, externally retained checkpoints | A fully compromised server can rewrite its local records and local hash chain together |

Security assumptions:

- Initial installation, trust-anchor distribution, and local-policy setup use a trusted manual administration channel. A node does not obtain its initial root of trust from the server it is supposed to authenticate.
- The node kernel, local root administrator, installed probe binary, and dependencies are not attacker-controlled. Local policy cannot constrain an already compromised node root account.
- The probe account cannot modify its executable, systemd unit, policy, trust anchors, helpers, or helper policies. It has no sudo privileges, Docker socket access, or equivalent indirect root authority.
- Nodes have a reliable clock and persistent storage. Significant clock rollback, deduplication-database corruption, or snapshot restoration requires explicit recovery rather than silently clearing security state.
- The remote server is not the source of local authority. Expanding allowlists, installing task implementations, and replacing trust anchors require node-local administration.
- The initial platform is Linux with systemd. Distribution support is added incrementally; unsupported data collectors return unavailable instead of falling back to a shell.

The defining distinction from a general-purpose C2 framework is its capability model: the protocol can express only predefined queries and separately enabled, limited maintenance actions. It has no primitive for payload delivery, commands, scripts, module uploads, interactive terminals, tunnels, or remote changes to local authority. Implementation and deployment must enforce this boundary; a project name or statement of intent cannot establish it.

**2. Architecture and component responsibilities**

```text
Administrator workstation
  CLI -- HTTPS + administrator session --> Central server (non-root)
                                           |-- Management API / RBAC
                                           |-- Enrollment / certificates
                                           |-- Typed queue / task signatures
                                           |-- Results / audit queries
                                           `-- SQLite / local audit log
                                                       ^
                                                       |
                         Outbound HTTPS / mTLS         |
                         Polling, heartbeats, results  |
                                                       |
Linux VPS                                              |
  Probe (account: argus) -------------------------------+
    |-- Certificate / signature verification / strict decoding
    |-- Local policy / task registry / deduplication / quotas
    |-- Native read-only collectors --> scoped /proc, /sys, system APIs
    |-- Fixed-resource reader --> locally allowlisted files
    |-- Local state / audit log
    `-- Optional Unix socket --> limited helper --> approved privileged data

Trusted manual channel: installation, policy, trust anchors, upgrades, stop
Offline root CA: certifies the online issuing CA; absent from the server app
Optional independent audit destination: separate administration and retention
```

The central server handles authentication, authorization, queueing, signing, results, and indexing. It does not interpret shell commands. The MVP uses one server process and SQLite with clear package boundaries. Modules in one process, or keys held online on the same machine, are not independent security boundaries.

Three server entry points are logically separated: the administrator HTTPS API, a briefly enabled enrollment API, and the probe API requiring client certificates. Separate listeners or hostnames may implement this separation; enrollment must not weaken client-certificate requirements across the probe API. The central server may expose service ports, but nodes expose no inbound network management port. Prefer terminating probe mTLS directly in the Go server. A future reverse proxy requires an explicit trusted-identity propagation design; internet-supplied identity headers are never authoritative.

Probes receive bounded tasks through HTTPS long polling. The first version avoids a custom multiplexed connection protocol. Heartbeats default to 30 seconds with jitter; reconnect attempts use exponential backoff capped at five minutes. Sampling intervals, the server address, and resource ceilings are local configuration. The server cannot supply new URLs, proxies, callback addresses, or sampling scripts. Probes reject cross-address redirects and do not use environment-provided proxy settings.

**3. Trust boundaries, privileges, and filesystem access**

| Boundary | Required validation | Untrusted claims or input |
| --- | --- | --- |
| CLI to management API | TLS, live session, role, payload size | Client-supplied administrator identity, role, or source IP |
| Unenrolled probe to enrollment API | Preinstalled server trust anchor, single-use token, CSR proof of private-key possession | Self-selected agent_id, certificate privileges, or certificate usages |
| Enrolled probe to probe API | Client certificate, registered fingerprint/serial, status, owning identity | An agent_id appearing only in a URL or request body |
| Server to probe | Signature, target identity, time, deduplication, structure, local policy, quotas | Claims that a task is already authorized or an emergency fix |
| Probe to host resources | Fixed resource ID, local mapping, safe open, read permission, output bounds | Arbitrary paths, wildcards, scripts, or dynamic service arguments |
| Probe to optional helper | Unix-socket peer UID, full task, independent helper policy and limits | A probe-supplied validated flag or arbitrary passed file descriptor |
| Audit records to viewer | Encoding, escaping, length limits, provenance labels | Control characters, embedded links, and self-reported node identities |

Local deployment requirements:

- Executables, configuration, and trust anchors reside in root-controlled locations such as `/usr/local/libexec/argus-c2/` and `/etc/argus-c2/`, without probe write access. Configuration defines task switches, resource-ID mappings, quotas, trust anchors, and local pause state.
- `/var/lib/argus-c2/` holds only identity keys, persistent deduplication state, and pending results. The directory uses mode 0700 and private keys mode 0600. Audit records go to a separate restricted directory or journald. Remote requests cannot choose state-file paths or arbitrary contents.
- The probe runs as `argus`, with no login shell, administrative groups, or generic capabilities. Its task interface provides no mechanism for starting arbitrary external programs.
- The systemd baseline includes `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict`, `ProtectHome=true`, `ProtectKernelTunables=true`, `ProtectKernelModules=true`, `ProtectControlGroups=true`, `RestrictSUIDSGID=true`, and `LockPersonality=true`, with empty capability sets. Write exceptions cover only required state directories. Resource and syscall restrictions are tightened after validating their effects.
- `ProtectSystem=strict` primarily restricts writes and does not replace a read allowlist. `ProtectHome=true` restricts access to user and root home directories. SSH coverage must not silently disable those restrictions. Option semantics follow the [official systemd manual source](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml).

File tasks accept logical IDs such as `auth_log`, `nginx_error`, or `sshd_config`, limited to short ASCII identifiers. Local configuration maps them to actual paths. No logs or home directories are allowlisted by default. `log.read` accepts only `log_id`, `max_bytes`, and `max_lines`; it offers no arbitrary path, file-download interface, arbitrary offset, or unbounded stream.

Safe file opening must prevent check/open races. The Linux MVP reader uses trusted directory descriptors and constrained `openat2` resolution: stay beneath the base directory and reject symlinks, magic links, and mount-point crossings. Each allowed mount uses a separately configured local base directory. After opening, check type, ownership, and size using the same descriptor, then perform bounded reads. Reject devices, FIFOs, sockets, directories, and hard links that violate policy. Establish and validate base directories from trusted paths at startup. If the kernel lacks the required safe-resolution semantics, disable affected file tasks rather than falling back to a separate check followed by ordinary open. These constraints follow the [Linux openat2 manual](https://man7.org/linux/man-pages/man2/openat2.2.html).

Using `filepath.Clean` or `EvalSymlinks` followed by a separate open is insufficient against races. `os.Root` may be evaluated for later implementation, but it does not automatically constrain mount crossings and requires a patched toolchain. See the [Go filesystem-access discussion](https://go.dev/blog/osroot) and [official advisory GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970). Files created by log rotation must pass the same checks again.

Private keys, password databases, probe identity material, and session storage cannot be added to file-read or hash allowlists. Logs can contain secrets, so raw-log upload is disabled by default. When enabled, apply source-specific filtering and redaction while recognizing that the central server can see approved output. File hashing is not a secret-probing interface.

SSH auditing reports configuration findings and authorized-key findings separately:

- Process only locally configured user IDs and explicit paths, without enumerating every user's home. A remote user ID cannot become an arbitrary filesystem path.
- Return file SHA-256 digests, public-key SHA-256 fingerprints, key types, owner UID/GID, permissions, and observation time. Do not return complete public-key lines or comments by default, and never read private keys.
- Analyze only allowed static configuration and allowed Include files, with recursion and size limits. Do not invoke `sshd -T`, `AuthorizedKeysCommand`, or external commands. Return partial/unsupported when Match rules, dynamic authorization, or other behavior cannot be fully interpreted; do not claim proof of the effective SSH configuration's safety.
- Distinguish missing files, access denial, parse failure, and changes during a read. A new fingerprint means a change was observed; an administrator decides whether it is unauthorized. Establish the first baseline through manual confirmation; server tasks cannot replace the local baseline.
- Under the default non-root and systemd-hardened deployment, unreadable `authorized_keys` files are reported as unavailable. If live auditing of those files is required, Phase 5 separately designs an optional, locally enabled read-only helper.

A helper adds a privileged trust boundary and attack surface. It must not become a general permission broker. The proposed read-only helper accepts only fixed SSH-audit tasks and local user IDs, independently validates the task and policy, safely opens files, and returns structured summaries. It provides no raw file descriptors, shell, network, write, dynamic-path, or execution capability. If root is necessary, only the helper holds that identity; the main probe remains non-root. Before implementation, document the helper's threat model, syscall and resource scope, and security review. This phase does not implement it.

Future service restarts use a separate narrow interface, an exact local unit allowlist, and a fixed systemd D-Bus method, without commands or environment overrides. Review aliases, dependencies, and startup configuration to avoid indirectly executing user-writable programs or configuration with root privileges. Restarts are disabled by default and exclude the probe, helpers, SSH, the system bus, and core system targets. A `service_id` allowlist alone cannot establish safe restart behavior; this capability is deferred until after the MVP.

**4. Proposed Go package structure**

This is a proposed future layout. The current phase creates documentation only.

```text
cmd/
  server/                  Server entry point
  agent/                   Node probe entry point
  cli/                     Administration CLI entry point
internal/
  protocol/                Versions, strict envelopes, parameters, results
  tasks/                   Static task registry and per-task validation
  policy/                  Local policy and resource-ID resolution
  agent/                   Polling, lifecycle, deduplication, execution
  agent/collectors/         Metrics, SSH, processes, and service collectors
  safefile/                Constrained file opening and reading
  server/                  Management/probe APIs, scheduling, results
  auth/                    Passwords, sessions, MFA, and RBAC
  enrollment/              Single-use tokens, CSRs, enrollment transactions
  identity/                Certificates, issuance, rotation, disablement
  tlsconfig/               Fixed TLS security policies for both endpoints
  signing/                 Fixed signature algorithm, encoding, verification
  audit/                   Events at both ends, hash chains, export
  storage/                 SQLite queries, transactions, migrations
  limits/                  Request, task, result, and rate limits
configs/                   Secret-free examples (future)
deploy/systemd/            Hardened service templates (future)
migrations/                Versioned server migrations (future)
docs/
  phase-1-design.md         This document
test/integration/          Cross-component tests (future)
test/fuzz/                 Corpora and fuzz tests (future)
```

Shared types stay in `internal`; no unused public `pkg` API is introduced. Task handlers must not bypass `policy` and `safefile` to use request input directly in system-resource access. The main probe task call chain must not depend on `os/exec` or evade its restrictions through cgo, interpreters, or dynamic libraries. Optional privileged programs receive separate entry points and packages, not a general operation dispatcher shared with the probe.

**5. Probe/server protocol, identity, and data flows**

Transport uses HTTPS JSON with TLS 1.3 required. Both endpoints verify certificate chains, validity, and appropriate usages; the probe also verifies the server name. There is no verification-bypass option, plaintext downgrade, or negotiation that enables command execution. Requiring TLS 1.3 is this project's deliberately narrow transport choice, informed by [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html).

The certificate hierarchy uses an offline root CA, a limited online issuing CA, and a separate client certificate for each probe. Server transport certificates, client-certificate issuance, and task signing use separate keys. A server-assigned URI SAN identifies each probe; the registry binds agent_id, enrollment_epoch, public-key fingerprint, and valid certificates. A certificate issued by the CA is insufficient unless it is also registered.

Enrollment flow:

1. Through a trusted local administration channel, install the probe, server CA/address, and task-signing public key. Initialize the server's first Admin through a local management operation. There is no publicly accessible first-administrator bootstrap backdoor.
2. An Admin creates a single-use enrollment token with at least 256 random bits and a default ten-minute lifetime. Show it only once; store only its hash and state. Do not put tokens in URLs, process arguments, logs, or shell history.
3. The probe generates its identity key locally and submits the token and CSR to the authenticated enrollment service. The private key never leaves the node.
4. The server verifies the token and CSR proof of private-key possession, assigns agent_id/epoch and certificate usages, and atomically binds the CSR fingerprint, creates the unique identity, and consumes the token. Do not return success before consuming the token.
5. Return the certificate chain and identity only after the transaction commits. If the response is lost, retrying the consumed token cannot create another node. An administrator invalidates the orphaned record and issues a new token, favoring a simple, auditable recovery flow.
6. Heartbeats, polling, result submission, and renewal subsequently use mTLS. Enrollment tokens never become persistent identities. The enrollment listener may be closed when no enrollment tokens are outstanding.

Certificates default to a 30-day lifetime, with renewal starting when ten days remain. Renewal uses a currently valid identity, preserves the same node identity, and checks that the node is enabled. Key rotation requires a new CSR and proof of the existing identity. If renewal fails and the certificate expires, remote tasks stop; recovery requires manual re-enrollment. These proposed lifetimes may be tightened during local deployment.

Disabling a node revokes all its certificates, cancels queued tasks, terminates active polls, and rechecks status on every API request and immediately before returning a task. Checking only at the TLS handshake is insufficient. The registered certificate-serial table implements application-level revocation; do not assume the TLS library automatically handles CRL/OCSP checks. Disablement cannot recall an already delivered, executing task; local execution limits still apply. A compromised server can also alter its own disablement records, so a local stop mechanism and independent manual recovery channel remain necessary.

Task signatures use a fixed Ed25519 algorithm through Go's standard cryptographic library, as defined in [RFC 8032](https://www.rfc-editor.org/info/rfc8032/). Requests cannot select an algorithm. Signing public keys are locally configured; an online server cannot replace trust anchors using a self-signed message.

The strict JSON signature envelope contains only `payload_b64` and `signature_b64`, both using unpadded Base64URL. The Ed25519 input is the fixed ASCII domain prefix `argus-c2/task/v1`, one NUL separator byte, and the decoded, original payload bytes. The server retains the exact bytes it signed, and the probe verifies those bytes rather than a deserialize-and-reserialize output. This avoids JSON ordering and representation ambiguity. The envelope defines a message format, not a new cryptographic algorithm.

Payload fields:

| Field | Constraint |
| --- | --- |
| version | Fixed integer 1; unknown versions are rejected |
| request_id | Random identifier with at least 128 bits of randomness and a fixed format |
| agent_id | Must equal the local node identity |
| enrollment_epoch | Must equal the current local enrollment epoch; old enrollments cannot reuse tasks |
| created_at | Integer UTC Unix seconds; no more than 30 seconds ahead of the local clock |
| expires_at | Integer UTC Unix seconds, later than created_at and no more than 300 seconds after it |
| task_type | Exact string from the task registry |
| task_version | Fixed integer version for the selected task |
| params | The task's strict parameter object |
| actor_id | Initiator identity for auditing; never authority to expand probe permissions |
| policy_digest | Must match the active local policy digest; otherwise reject and require resubmission |

The probe computes policy_digest as a SHA-256 digest of its validated, active local policy and reports it in heartbeats. The server only echoes it. The digest covers task switches, resource mappings, and limits, excludes private keys, and changes immediately when policy changes. It prevents dispatch based on stale policy; knowing it grants the server no additional authority.

Limit the outer request to 16 KiB, decoded payload to 8 KiB, params to 4 KiB, and JSON nesting depth to eight. Reject unknown fields, duplicate keys, case variants, trailing JSON, invalid UTF-8, invalid numeric forms, missing required fields, and disallowed nulls. Successful decoding into a Go struct is not sufficient for strict validation. Starting in Phase 2, each task receives a versioned JSON Schema, including `additionalProperties: false`, and equivalent server/probe validation checked against shared negative-test corpora. Network peers cannot supply new schemas.

A valid signature must still pass local policy. A compromised server can generate valid signatures, so signing provides provenance and integrity beyond the transport layer but does not constrain the signing server's authority. Local enforcement provides that constraint.

Proposed task registry:

| TaskType | Strict parameters | Behavior and limits | Scope |
| --- | --- | --- | --- |
| system.info | Empty object | OS, kernel, architecture, boot time; no environment variables | MVP |
| system.metrics | Empty object | CPU, memory, locally configured disks/interfaces; locally fixed sampling window | MVP |
| process.list | limit, 1-1000 | PID, UID, process name, limited metrics; no full command lines, environment, or memory | MVP |
| network.listeners | limit, 1-1000 | Local addresses, protocols, accessible process associations; no remote probing | MVP |
| service.status | service_id | Exact local unit mapping; bounded structured properties | MVP |
| log.read | log_id, max_bytes 1-65536, max_lines 1-500 | Bounded tail of an allowed log; no resources configured by default | MVP |
| file.hash | file_id | Fixed SHA-256 over an allowed regular file; default maximum input 16 MiB | MVP |
| ssh.audit | profile_id | Locally configured files/users; coverage, fingerprints, permissions, findings | MVP, permission-limited |
| service.restart | service_id | Fixed system API; separate privilege boundary and restart limits required | Post-MVP, disabled by default |
| package.updates | Empty object | Existing local package metadata with cache timestamp; no refresh or installation | Post-MVP, distribution-specific |

Post-MVP tasks are not registered in versions that do not implement them; requests receive an unsupported response. String IDs are at most 64 bytes and use a predefined ASCII character set. All listed fields for parameterized tasks are required, with no extras. New fields require a new task version; compatibility must not depend on silently ignoring unknown fields.

The probe processing sequence is fixed: bounded read; strict envelope parsing; fixed-algorithm signature verification; payload structure/version validation; identity/epoch/time checks; task and parameter validation; local policy and quotas; atomic persistence of acceptance and local audit intent; fixed-handler invocation; persistence of result and completion audit; bounded retries of result submission. Unauthorized requests cannot trigger a handler, file opening, or system action.

Deduplication and crash semantics:

- Maintain a local unique index over `(enrollment_epoch, request_id)` and store the payload digest. Reject the same ID with different contents.
- Persist execution state before starting. Duplicate delivery never executes again. Cached results may be resubmitted, which is result retransmission rather than acceptance of a duplicate task.
- States include accepted, running, succeeded, failed, rejected, expired, and indeterminate. An accepted/running record left across a restart becomes indeterminate and is not automatically rerun. Future side-effecting tasks require administrator inspection before a fresh request ID is used.
- Do not start a task at or after expires_at. Its deadline is the earlier of the local task timeout and expires_at. Defaults are 30 seconds per task and five seconds for lightweight queries. Cancellation cannot guarantee reversal of a side effect already submitted to the operating system; record uncertainty accurately.
- Retain completed deduplication records at least until `expires_at + 24 hours`; do not automatically delete unresolved execution records. Persist a clock high-water mark and stop accepting tasks after a significant rollback. Snapshot recovery requires a local identity-epoch reset and re-enrollment. Replay protection is not guaranteed against malicious rollback of both disk and clock.
- If the deduplication database is unavailable, audit intent cannot be persisted, or the execution queue is full, reject new tasks while retaining read-only health reporting. Never downgrade to unrecorded execution.

Task results include request_id, agent_id, epoch, task_type, start/end times, status, structured data, a stable error_code, truncated, and the actual policy_digest. Ordinary results are capped at 256 KiB, with raw-log contents additionally capped at 64 KiB. The server binds the submitter to its mTLS identity and checks assignment ownership; it rejects results for other nodes' tasks and attempts to overwrite a terminal result. Probe results rely on mTLS transport authentication by default and do not independently prevent a fully compromised server from forging history.

Each node defaults to one executing task at a time, 30 accepted tasks per minute with a burst of five, at most two log reads per minute, an 8 MiB daily log-output budget, and 32 MiB of locally pending results. The probe enforces every ceiling independently. A server may request smaller values but cannot increase the local limits. Separate server limits bound accounts, nodes, payload sizes, and queue capacity. Deadlines must reach collectors and readers; an HTTP timeout alone must not leave unbounded background work.

Proposed API:

| Entry point and path | Method | Authorization and semantics |
| --- | --- | --- |
| Management `/api/v1/auth/login`, `/api/v1/auth/logout` | POST | Authenticate or revoke the current session; rate-limit login |
| Management `/api/v1/agents`, `/api/v1/agents/{id}` | GET | Admin and ReadOnly inspect already collected data |
| Management `/api/v1/tasks` | POST | Admin only; explicitly target one node and a typed task |
| Management `/api/v1/tasks`, `/api/v1/tasks/{id}` | GET | Admin and ReadOnly query existing tasks/results |
| Management `/api/v1/audit` | GET | Admin and ReadOnly; bounded pagination |
| Management `/api/v1/enrollment-tokens` | POST | Admin only; create a single-use token |
| Management `/api/v1/agents/{id}/disable` | POST | Admin only; revoke identity and cancel queued tasks |
| Enrollment `/api/v1/enroll` | POST | Authenticated server TLS, single-use token, CSR |
| Probe `/api/v1/agent/heartbeat` | POST | mTLS; server derives node identity from the certificate |
| Probe `/api/v1/agent/tasks/poll` | POST | mTLS; long poll returns one signed task or no task |
| Probe `/api/v1/agent/results` | POST | mTLS; only submit results for this node's assigned tasks |
| Probe `/api/v1/agent/certificate/renew` | POST | mTLS; renew or rotate only this node's identity |

ReadOnly can view existing data only; refreshing a view must not silently dispatch a new task. Locally predefined basic-metric sampling is fixed behavior authorized at installation, not a server-supplied script, cron schedule, or generic scheduled task. Tasks expiring while a node is offline are discarded rather than executed after reconnection.

Authentication and storage: administrator passwords use Argon2id with independent random salts and versioned hash parameters, calibrated on the target server while limiting concurrent password checks. See [Argon2 definitions and parameter guidance](https://www.rfc-editor.org/rfc/rfc9106.html). Sessions use random opaque tokens, stored only as hashes, with proposed defaults of 30 minutes idle and eight hours maximum lifetime. Logout, password changes, and role changes revoke sessions. The CLI stores credentials in the OS credential store or a permission-restricted file, never logs or command arguments. A future browser interface uses Secure/HttpOnly/SameSite cookies and CSRF protection. Optional TOTP, once enabled, cannot be bypassed through a login fallback. Encrypt TOTP seeds and store only hashes of recovery codes.

The MVP database contains agents, agent_certificates, tasks, task_results, users, sessions, audit_events, enrollment_tokens, and schema_migrations. Commit a task and its audit intent in one transaction before signing and dispatch; enrollment-token consumption is also atomic. Use parameterized SQL, foreign keys, uniqueness constraints, bounded pagination, and versioned migrations. Migrations run through local administration and have no public API. Server backups cover a consistent SQLite snapshot and corresponding keys; restoration invalidates old sessions and reconciles task state. Keep private keys out of the repository and do not present same-host encryption as protection against full server compromise.

Audit events include timestamp, sequence number, administrator_id, source_ip, agent_id, task_type, sanitized parameters, result status/summary, request_id, policy_digest, and execution times. Derive source IP from the network peer, accepting forwarded headers only from configured trusted proxies. Record authentication, enrollment, role changes, node disablement, task acceptance/rejection/completion, certificate rotation, and local-policy changes. A probe records the signed actor_id and server peer it observed, labeling administrator-origin metadata as server-asserted.

Reading existing task results, log results, and audit records also creates access-audit events. Record query scope and outcome summaries, not duplicate sensitive content. Administrative operations unrelated to a node have an explicit event type and not-applicable agent_id/task_type, rather than a fabricated task identifier.

Audit records exclude passwords, tokens, private keys, complete sensitive logs, and arbitrary stack traces. The server audit interface is append-only; serialized sequence numbers and a hash chain help detect anomalies. Independently retained checkpoints make whole-chain rewriting more detectable. Probes retain local audit records for at least 30 days and the server for at least 90 days, subject to bounded, provisioned storage and explicit rotation records. Server acknowledgement must not immediately delete local evidence. Insufficient audit capacity pauses new tasks. The first version does not claim database-administrator-proof storage and exposes no remote probe-audit clearing function.

**6. Security invariants and validation criteria**

| Invariant | Required future validation |
| --- | --- |
| The protocol cannot express arbitrary execution or writes | Review endpoints and task registry; negative tests for commands, scripts, and paths; review handler dependencies |
| A server signature cannot expand local authority | A malicious test server holding the valid signing key still fails to submit unauthorized tasks |
| The probe cannot modify its local security policy or executable | Linux permission tests deny writes to policy, program files, and systemd units |
| Each task accesses only explicitly allowed resources | Tests for unauthorized IDs, absolute paths, `..`, symlinks, magic links, hard links, mount crossings, and rotation races |
| Every access is bound to the current node identity | Wrong agent_id/epoch, invalid/expired/unregistered certificates, disabled nodes, and revocation during active connections |
| Unknown or ambiguous protocol input is rejected | Unit and fuzz tests for unknown tasks/versions/fields, duplicate keys, case variants, malformed JSON, excessive depth, and oversized bodies |
| Expiration and persistent deduplication survive restart | Expired/future requests, duplicate IDs, same ID with different content, concurrent delivery, clock rollback, and fault injection |
| Execution is preceded by a durable record | Full databases, audit-write failures, simulated crashes; a task cannot start without a persisted intent |
| Role restrictions are enforced by the backend | ReadOnly is denied task creation and administrative actions, including manual refreshes that would trigger read tasks |
| SSH auditing cannot modify authorized keys | Compare file contents and metadata before/after tasks; clearly report access denial and partial parsing |
| Nodes control their own resource ceilings | Timeout, oversized results, log budgets, full disks, disconnected retries, and server attempts to raise limits |
| Unsupported features never silently weaken the model | Missing APIs, permissions, or safe path resolution return unavailable rather than invoking a shell |

Validation layers include Go unit tests, multi-node integration tests with real TLS, permission and systemd checks in Linux VMs, and fuzzing of strict JSON, SSH public-key/configuration parsing, and protocol decoding. A Windows development machine cannot substitute for Linux security-semantics validation. Additional testing follows actual changes and failures rather than reproducing implementation logic without meaningful coverage.

Choose a supported Go stable release with current security fixes at implementation time and pin the specific version in Phase 2. Pin dependencies and run vulnerability checks. The [official Go release policy](https://go.dev/doc/devel/release) defines support windows; the existence of an API in an old toolchain is not a reason to deploy an unsupported release.

A server-compromise exercise must demonstrate that an attacker with Admin authority and the signing key still cannot add/remove SSH keys, write arbitrary files, execute commands, upload programs, expand allowlists, or redirect probes to arbitrary destinations. It must also document the approved information the attacker can obtain and the availability damage it can cause. These tests are requirements, not claims of already completed validation.

**7. MVP scope and subsequent phases**

The MVP is single-tenant, with one central server, SQLite, owned Linux/systemd nodes, and CLI administration. It includes explicit enrollment, per-node mTLS, node disablement, heartbeats, fixed metric sampling, typed read-only tasks, persistent deduplication, auditing at both ends, Admin/ReadOnly roles, and constrained resource reads. SSH auditing includes fingerprints and permissions, while reporting gaps under default permissions. Protected files require a separately enabled and validated read-only helper. Default deployment does not promise access to every SSH-related path on every node.

| Phase | Deliverables | Security gate |
| --- | --- | --- |
| 1: current | This design document | All eight deliverables and compromise boundaries defined; no implementation code |
| 2 | Go module, strict protocol types, identity, mTLS | Pinned toolchain, certificate validation, negative certificate tests |
| 3 | Enrollment, heartbeats, system.info, system.metrics | Atomic enrollment, fixed local sampling, no unprotected remote-task interface |
| 4 | Typed dispatch, local policy, deduplication, auditing, bounded read-only collection | Malicious-server negative tests, crash behavior, safe filesystem boundaries |
| 5 | SSH configuration/key auditing, service status | Explicit unreadable scope; separate helper design and review if needed |
| 6 | CLI, full administrator authentication, RBAC, optional TOTP | ReadOnly cannot initiate tasks; session revocation and login-abuse tests |
| 7 | Linux hardening, security integration tests, fuzzing, documentation | Server-compromise and recovery exercises completed before real VPS deployment |

Phase ordering must not create a temporarily unauthenticated public service. Before Phase 6, management interfaces are tested only in isolated development environments, on loopback, or through local Unix sockets. Do not expose them to the internet before authentication, RBAC, and auditing are complete. Basic structural and identity checks accompany each relevant interface rather than waiting until Phase 7.

After the MVP, separately evaluate service restarts, distribution-specific package-update reporting, a read-only dashboard, and independent audit aggregation. At the start of every phase, explain what is being built, its rationale, and its risks before writing that phase's code.

**8. Intentionally excluded features**

- Arbitrary shells, command-string execution, remote terminals, PTYs, uploaded scripts, and generic exec APIs.
- File managers; arbitrary file upload, download, read, or write; remote modification of SSH keys, accounts, sudo configuration, or system security controls.
- Generic cron jobs, remote scheduled commands, arbitrary orchestration scripts, dynamic plugins/bytecode/payloads, and server-driven probe self-updates.
- Automatic discovery or mass enrollment, unrelated-host scanning, lateral movement, port forwarding, SOCKS/proxy tunnels, and arbitrary-destination network requests.
- Hidden operation, malicious persistence, anti-forensics, log clearing, bypassing consent or security controls, and antivirus/EDR evasion.
- Privilege escalation, process injection, credential collection, browser-data collection, keylogging, screenshots, and process-memory capture.
- A shared secret across all probes, production TLS-verification bypass, a wholly root-run probe, or generic sudo access to compensate for missing privileges.
- Remote expansion of allowlists, remote disabling of auditing/rate limits/permission restrictions, remote replacement of trust anchors or baselines, and an emergency mode that enables general-purpose capabilities.

A visible, stoppable, manually installed systemd service is ordinary deployment. Hidden services or mechanisms that resist removal are excluded. Future requests beyond these boundaries should receive a narrowly scoped defensive alternative instead of a generic execution primitive added to the protocol.
