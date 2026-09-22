# Argus-C2

A self-hosted remote administration and incident-response control plane for Linux VPS infrastructure you own and administer.

Argus-C2 is planned as a Go-based system comprising a central server, lightweight node probes, and an administration CLI. Its scope covers system visibility, SSH configuration checks, authorized-key auditing, and explicitly authorized, narrowly defined maintenance tasks.

The central design goal is: **compromising the management server must not give an attacker arbitrary command execution or arbitrary filesystem write access across enrolled nodes.** Each probe independently validates incoming tasks against a locally controlled policy that defines its maximum authority.

**Project status**

Phase 1 architecture and security design is complete. This repository currently contains documentation only; server, probe, and CLI implementations and deployable releases are not yet available. The capabilities below are planned, and the security goals still require implementation and testing.

See the [Phase 1 architecture and security design](docs/phase-1-design.md) for the full specification.

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

SSH auditing does not modify `authorized_keys`. Results must identify coverage gaps when permissions are insufficient or configuration cannot be fully interpreted. Reads requiring additional privilege belong in a separately reviewed, narrowly scoped helper; the main probe remains non-root.

**Security design**

- **Explicit enrollment and individual identities.** A short-lived, single-use token enrolls a node. Each probe receives its own client certificate, uses mTLS afterward, and can have its certificates revoked or its identity disabled.
- **Locally controlled authority.** Tasks have predefined types and strict parameter schemas. Unknown types, extra arguments, unauthorized resources, and oversized requests must be rejected. The server cannot remotely expand allowlists or replace trust anchors.
- **Least privilege.** Probes run under a dedicated non-root account with systemd hardening. Local administrators control program files and security policy. Privileged helpers expose only explicitly defined operations.
- **Signatures and replay protection.** Tasks bind a node identity, enrollment epoch, request ID, and validity window. Signature verification and persistent deduplication prevent repeated execution; tasks left in an uncertain state after a crash are not automatically rerun.
- **Separated administrator roles.** The planned roles are Admin and ReadOnly. ReadOnly can inspect existing data but cannot initiate tasks. Authentication uses strong password hashing, revocable sessions, and optional TOTP.
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
| 2 | Go module, shared protocol types, node identity, and mTLS | Not implemented |
| 3 | Enrollment, heartbeats, system information, and basic metrics | Not implemented |
| 4 | Typed task dispatch, local policy, persistent deduplication, and auditing | Not implemented |
| 5 | SSH configuration and authorized-key auditing, service status | Not implemented |
| 6 | Administration CLI, administrator authentication, and RBAC | Not implemented |
| 7 | Linux deployment hardening, security tests, fuzzing, and documentation | Not implemented |

Each phase starts by explaining its scope, design rationale, and security risks before implementation and validation. Identity checks and input validation accompany the interfaces that need them. Management interfaces remain restricted to local or isolated development environments until authentication, authorization, and auditing are complete.

Planned tests cover path traversal, symlink escape, malformed requests, replay, node identity mismatches, invalid or revoked certificates, role violations, resource exhaustion, and a malicious server holding a valid signing key attempting to bypass local policy.

**Repository contents**

```text
README.md                 Project overview, scope, and roadmap
docs/
  phase-1-design.md        Complete Phase 1 architecture and security design
```

The proposed Go package layout, API, enrollment flow, task format, and security validation requirements are documented in the [design specification](docs/phase-1-design.md). Build, installation, and usage instructions will be added as the corresponding implementations become available.
