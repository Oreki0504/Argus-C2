# Argus-C2

A self-hosted remote administration and incident-response control plane for Linux VPS infrastructure you own and administer.

Argus-C2 is planned as a Go-based system comprising a central server, lightweight node probes, and an administration CLI. Its scope covers system visibility, SSH configuration checks, authorized-key auditing, and explicitly authorized, narrowly defined maintenance tasks.

The central design goal is: **compromising the management server must not give an attacker arbitrary command execution or arbitrary filesystem write access across enrolled nodes.** Each probe independently validates incoming tasks against a locally controlled policy that defines its maximum authority.

**Project status**

Phases 1 through 6 are implemented: architecture and protocol foundations, explicit enrollment, persistent identities, mTLS heartbeats, and signed dispatch of four read-only tasks: `system.info`, `system.metrics`, `ssh.audit`, and `service.status`. A separate HTTPS management API and CLI now use Argon2id passwords, revocable sessions, and Admin/ReadOnly roles. SSH and service inspection require explicit local opt-in and resource mappings. Probes enforce local policy, persistent replay protection, execution limits, and durable result delivery. Both ends keep bounded hash-chained audit records. Deployment hardening remains Phase 7 work. This is a loopback-only development prototype, not a production-ready release. The full capabilities below remain the roadmap.

See the [Phase 1 architecture and security design](docs/phase-1-design.md) for the full specification.

Start with the [Phase 6 administration guide](docs/phase-6-implementation.md) for account bootstrap, CLI login, roles, sessions, and recovery. The [Phase 5 guide](docs/phase-5-implementation.md) covers SSH observations and service queries, and the [Phase 4 guide](docs/phase-4-implementation.md) provides enrollment/dispatch setup and replay recovery. Earlier guides retain their historical scope. The toolchain baseline is Go 1.27.1, with pinned dependencies in go.mod/go.sum.

**Architecture**

```mermaid
flowchart LR
    Admin[Administrator] --> CLI[Administration CLI]
    CLI -->|HTTPS / administrator authentication| Server[Central server]
    Server --> DB[(SQLite)]
    Server --> ServerAudit[Server audit log]

    subgraph VPS[Explicitly enrolled Linux VPS]
        Probe[Node probe] --> Policy[Local policy and task validation]
        Policy --> Collector[Predefined task handlers]
        Collector --> Resources[Allowed system data and files]
        Policy --> LocalAudit[Local audit log]
    end

    Probe -->|Outbound mTLS / polling, heartbeats, results| Server
    Server -.->|Signed task in polling response| Probe
```

| Component | Responsibility |
| --- | --- |
| Central server | Node enrollment, identity management, administrator authentication, task dispatch, result queries, and auditing |
| Node probe | Initiate outbound connections, independently enforce local policy, collect approved data, and maintain a local audit log |
| Administration CLI | Inspect nodes and results, submit allowed tasks, and manage enrollment and node status |
| Read-only web dashboard | Optional later interface for viewing data already collected |

Probes expose no inbound network management port. In code and protocol identifiers, `agent` refers to the resident node client; this documentation calls it a probe.

**Planned capabilities**

The MVP focuses on read-only queries and auditing. Each node locally defines which files, logs, services, and users are in scope.

| Task | Purpose | Planned scope |
| --- | --- | --- |
| `system.info` | Report operating system, kernel, architecture, and boot time | MVP |
| `system.metrics` | Report CPU, memory, disk, and network metrics | MVP |
| `process.list` | Report limited process information, excluding environment variables and process memory | MVP |
| `network.listeners` | Report listening ports on the local node | MVP |
| `service.status` | Query allowlisted service status | MVP |
| `log.read` | Read a bounded tail of an allowlisted log | MVP |
| `file.hash` | Calculate the SHA-256 digest of an allowlisted file | MVP |
| `ssh.audit` | Inspect configured SSH settings, authorized-key fingerprints, file ownership, and permissions | MVP, subject to local read permissions |
| `service.restart` | Restart an explicitly allowed service | Post-MVP; disabled by default and subject to a separate security review |
| `package.updates` | Inspect update availability using local package metadata | Post-MVP, with distribution-specific adapters |

SSH auditing does not modify `authorized_keys`. Implemented reports contain bounded fingerprints, metadata, local baseline comparisons, and selected static configuration observations. They identify coverage gaps and do not claim to resolve effective sshd configuration. Service queries inspect only locally mapped, already loaded units. Reads requiring additional privilege remain unavailable; a [separate helper design](docs/phase-5-helper-design.md) records future review requirements, and no privileged helper is implemented.

**Security design**

- **Explicit enrollment and individual identities.** A short-lived, single-use token enrolls a node. Each probe receives its own client certificate, uses mTLS afterward, and can have its certificates revoked or its identity disabled.
- **Locally controlled authority.** Tasks have predefined types and strict parameter schemas. Unknown types, extra arguments, unauthorized resources, and oversized requests must be rejected. The server cannot remotely expand allowlists or replace trust anchors.
- **Least privilege.** Probes run under a dedicated non-root account with systemd hardening. Local administrators control program files and security policy. Privileged helpers expose only explicitly defined operations.
- **Signatures and replay protection.** Tasks bind a node identity, enrollment epoch, request ID, and validity window. Signature verification and persistent deduplication prevent repeated execution; tasks left in an uncertain state after a crash are not automatically rerun.
- **Separated administrator roles.** Admin can submit existing tasks and perform node/token administration. ReadOnly can inspect existing data but cannot initiate tasks. Authentication uses Argon2id password hashing and revocable sessions, with live authorization and mutations in the same transaction. Account provisioning stays local; optional TOTP remains unimplemented.
- **Independent auditing and limits.** Both server and probe record operations and outcomes. Probes independently limit execution time, concurrency, read volume, and response size. Audit logs exclude passwords, tokens, and private keys.

A task signature proves that a trusted key signed the message. If the server and signing key are compromised, containment still depends on the probe's local policy. An attacker may obtain data already authorized for upload, falsify the central view, or affect availability. The design does not claim protection when node root, the kernel, or the probe itself is already compromised.

Audit records are maintained at both ends with tamper-detection measures. A server-local log and hash chain cannot independently establish trustworthy history after full server compromise. See the [complete design](docs/phase-1-design.md) for assumptions, recovery behavior, and validation requirements.

**Scope boundaries**

The project is intended for machines you own or are explicitly authorized to administer. Its protocol deliberately excludes:

- Arbitrary shells, remote terminals, generic command execution, uploaded scripts, and arbitrary scheduled commands.
- Arbitrary file reads or writes, file managers, and remote modification of SSH authorized keys, accounts, or security configuration.
- Remote expansion of local privileges, dynamic payload or plugin delivery, and server-driven probe self-updates.
- Automatic discovery or mass enrollment, unrelated-host scanning, lateral movement, proxy tunnels, and port forwarding.
- Stealth, malicious persistence, log clearing, security-product evasion, privilege escalation, and process injection.
- Credential or browser-data collection, keylogging, screenshots, and process-memory capture.

**Roadmap**

| Phase | Deliverables | Status |
| --- | --- | --- |
| 1 | Threat model, architecture, protocol, trust boundaries, and MVP scope | Design documented |
| 2 | Go module, shared protocol types, node identity, and mTLS | Implemented; local development only |
| 3 | Enrollment, heartbeats, system information, and basic metrics | Implemented; local development only |
| 4 | Typed task dispatch, local policy, persistent deduplication, and auditing | Implemented for two read-only task types; local development only |
| 5 | SSH configuration and authorized-key auditing, service status | Implemented with explicit local opt-in, bounded observations, and coverage gaps; local development only |
| 6 | Administration CLI, administrator authentication, and RBAC | Implemented with local account provisioning and revocable sessions; optional TOTP deferred |
| 7 | Linux deployment hardening, security tests, fuzzing, and documentation | Not implemented |

Each phase starts by explaining its scope, design rationale, and security risks before implementation and validation. Identity checks and input validation accompany the interfaces that need them. Management interfaces remain restricted to local or isolated development environments until authentication, authorization, and auditing are complete.

Current tests cover strict parsing and signatures, certificate/enrollment boundaries, heartbeat identity binding, real mTLS task delivery, persistent replay protection, concurrent duplicates, interrupted-task recovery, local policy rejection, audit tampering and write failures, result limits and acknowledgments, and disabled nodes on established connections. Inspection tests cover file/link/rotation boundaries, redacted observations, baseline drift, bounded D-Bus decoding, and a real Linux systemd query. Administration tests add real TLS, backend RBAC, session revocation/expiry, persistent login limits, credential storage, and audit transaction failures. Linux/Windows CI, the Linux race detector, a vulnerability scan, and bounded fuzz tests exercise the implementation. Phase 7 adds deployment resource controls and broader compromise/recovery exercises.

**Repository contents**

```text
cmd/                      Server, probe, enrollment, development keys, local operator tools
internal/                 Protocol, TLS, enrollment, SQLite, policy, task engine, audit, collectors
schemas/                  Versioned protocol JSON Schemas
examples/                 Explicit local telemetry and task policy
test/integration/         Real mTLS connection tests
.github/workflows/        Linux and Windows validation
docs/
  phase-1-design.md        Target architecture and security design
  phase-2-implementation.md Implemented scope and local development guide
  phase-3-implementation.md Enrollment, heartbeat, storage, and telemetry guide
  phase-4-implementation.md Typed tasks, local policy, replay state, and audit guide
  phase-5-implementation.md SSH observations, local resource mappings, and service status
  phase-5-helper-design.md Privileged helper constraints; no helper implemented
  phase-6-implementation.md Administrator CLI, authentication, sessions, and RBAC
```

The target API, enrollment flow, task format, and security requirements are documented in the [design specification](docs/phase-1-design.md). Follow the [current administration guide](docs/phase-6-implementation.md) to create local accounts, authenticate the CLI, and manage the existing read-only task flow. Production installation instructions will be added after the corresponding security gates are complete.
