# Security boundaries

[Documentation](../README.md) · [Architecture](architecture.md) · [Configuration](configuration.md) · [Operations](operations.md)

Argus-C2 supports diagnostics on explicitly authorized Linux hosts. Its controls protect node identity, management permissions, diagnostic data in transit, and the agent's local execution limits. The model assumes trusted local administrators control the programs, CA, and policy, and that the operating system and agent are not compromised.

## Trust and controls

| Property | Current mechanism | Boundary |
| --- | --- | --- |
| Network confidentiality, integrity, and server identity | Standard Go TLS, minimum TLS 1.3, CA and name validation | Trust anchors must be distributed through a trusted channel |
| Node identity | Per-node certificate, identity URI, fingerprint, and active-status checks | A leaked node key requires disabling and reenrollment |
| Management permissions | Named high-entropy bearer tokens; Admin / ReadOnly | Possession grants the account's permissions; no automatic expiry or MFA |
| Agent execution scope | Six fixed Go collectors, strict task parameters, local allowlist, non-root execution | Local OS permissions and runtime restrictions determine visibility |
| Repeated delivery and interruptions | ID/node binding, expiry, SQLite uniqueness, persistent execution records | No exactly-once promise; old snapshots can break continuity |
| Visibility of important changes | Structured audit committed with state changes, bounded retention | Database administrators can alter records; history is not tamper-proof |

The server is trusted to deliver tasks. The protocol has no independent task signature or policy-hash negotiation. A fully compromised server can request locally permitted diagnostics, suppress or falsify its central view, and affect availability. The fixed protocol provides no remote-command, file-write, policy-expansion, or dynamic-code interface, but these restrictions do not guarantee resistance to implementation vulnerabilities.

Compromise of node root, the kernel, the agent executable, or local policy is outside these guarantees. A non-root agent limits execution privileges. The project does not provide process hiding, protection bypass, privilege escalation, or covert access.

## Authentication in deployment

All routes share one HTTPS listener. TLS uses `VerifyClientCertIfGiven`: connections without a client certificate can reach enrollment and management routes; any supplied certificate must pass TLS verification. Every `/v1/agent/*` route additionally requires a verified client certificate. An administrator token cannot replace it.

Every node operation checks certificate validity, fingerprints, and disabled status. Existing connections therefore cannot bypass node disabling. Standard TLS validates the trust chain; application checks add node authorization. There is no trust-on-first-use, `insecure` mode, plaintext fallback, or proxy-header substitute for a node identity.

Administrator configuration stores only SHA-256 digests of tokens generated from a cryptographically secure random source. This is not password authentication. Give each administrator a separate token and use ReadOnly for observation. To revoke an account, remove its record and restart the server; configuration changes are not hot-reloaded.

## Single CA and renewal

Initialization creates a self-signed CA and a separate server key and certificate. Defaults are five years for the CA, one year for the server certificate, and 30 days for agent certificates, bounded by CA expiry. Certificate lifetimes are code defaults, not JSON settings.

When less than seven days remain, the agent attempts renewal with the same private key. It validates the response, syncs a temporary certificate file, atomically replaces the certificate, and rebuilds its HTTPS client. The server accepts the previous certificate until its original expiry to recover from lost responses. This is a retry window, not immediate revocation of the previous certificate.

Renewal does not replace the private key and cannot repair key compromise. Disable a suspected identity and enroll with a new directory and key. Expired offline identities and lost agent state also require manual reenrollment. There is no CRL/OCSP service, automatic CA replacement, multigeneration trust set, or remote trust-root update.

## Online root exposure and incident response

The current server loads the root CA signing key at runtime for enrollment and renewal. `LoadCredential` restricts file delivery but the server process can still use that key. A server compromise can therefore expose the trust anchor as well as administrator configuration and diagnostic data. A stolen root key can mint a server certificate accepted by clients; node fingerprints still constrain previously registered node identities, but cannot make a compromised management server trustworthy. Root expiry and node disabling do not revoke a leaked root from client trust stores.

Use these manual recovery procedures:

| Incident | Containment and recovery |
| --- | --- |
| Node key/certificate leaked | Disable the node through a trusted management path; this rejects current and previous fingerprints on existing connections. Stop and preserve local state, rebuild the affected host as needed, and reenroll with a new key and node ID. Renewal with the same key is insufficient. |
| Server TLS leaf key leaked, root still trusted | Restrict agent access, replace the server key/certificate and restart. There is no leaf CRL/OCSP check in clients: replacement alone does not make the stolen unexpired certificate untrusted. Maintain network containment through expiry or coordinate a new trust anchor and reenrollment if immediate cryptographic rejection is required. |
| Root CA key leaked or its integrity uncertain | Restrict both agent and management access, preserve evidence, and rebuild the server from a trusted environment. Generate a new root and leaf keys, distribute the new trust anchor through an independent authenticated channel, remove the old anchor, rotate administrator tokens, and reenroll nodes. Do not use the suspected server to distribute trust. |
| CA material lost, no evidence of compromise | Restore the separately protected matching CA certificate/key and server materials into an isolated environment. Verify certificate fingerprints, key matching, validity, permissions, and independent revocation records before reopening access. Without a trusted copy, establish new trust and identities. |

A SQLite backup does not include CA private keys. Restoring old state does not replay later revocations; follow [database restoration](operations.md#restore-the-server-database), keeping agent ingress restricted until administrator permissions and node disabling have been reconciled. Keep incident and revocation records independent of the database being restored. There is no automated PKI disaster-recovery service.

## Offline Root and Online Intermediate plan

This is a proposed next PKI design, **not supported by the current configuration/issuer flow**:

1. Establish an offline root that permits an intermediate, with encrypted recovery copies and a documented access process. The current generated root has a zero path-length constraint and cannot support a valid intermediate chain; this requires a newly provisioned root and coordinated trust replacement. Use its key only to issue/replace constrained intermediate certificates; keep its fingerprint independently recorded.
2. Give the server an online intermediate signing key with `CA=true`, certificate-signing usage, a zero path-length constraint, and a shorter operational lifetime. Use distinct leaf keys; do not make the server TLS key a CA key. Bound leaf validity by issuer validity.
3. Separate the root trust bundle, issuer certificate/chain, and issuer key in configuration. Enrollment and renewal responses must supply the complete usable leaf/intermediate chain. Verify issuer-chain constraints at startup and after renewal without weakening URI, EKU, node fingerprint, or transaction authorization checks.
4. Define intermediate replacement and overlap, expired-chain behavior, and compromised-intermediate rejection before deployment. Merely issuing another intermediate leaves a stolen unexpired intermediate trusted under the same root; choose and implement an explicit distrust mechanism or coordinated trust replacement. Do not claim CRL/OCSP support until it exists and is tested.
5. Test offline-root absence on the server, wrong/missing chains, expired issuer and leaf, renewal response loss, old/current node fingerprint rejection, intermediate compromise, and isolated CA/database restore. Document a manual rollout that preserves agent identity state or explicitly reenrolls it.

The existing single `ca`/`issuer_key` setup does not implement this separation. Do not substitute an intermediate into the current deployment and assume chain delivery or rotation works. This round documents the design and operational response; it does not add a CA service, automatic root distribution, or a compatibility matrix.

## Local permissions and file boundaries

The supplied units use separate users, empty capability sets, `NoNewPrivileges`, read-only system paths, and process/memory limits. The agent writes only to its own state directory and needs certificate-file write access for renewal. Local administrators retain control of policy, CA files, and programs.

SSH file access uses constrained directory descriptors and `openat2`, checking paths, file types, link counts, ownership, directory replaceability, and consistency before and after reading. SSH resource bases cannot be `/proc`, `/sys`, `/dev`, `/run`, or their descendants. System, process, and network collectors read predefined system paths separately; those collectors are not general-purpose file readers.

Service queries use only the fixed system bus and already loaded services, without subprocesses. SSH reports omit raw content and private keys; process reports omit arguments, environment, and memory; network collection sends no probes. Reports still contain diagnostic metadata and some key/file fingerprints. Management account permissions control access to those reports.

## Meaning of resource limits

Collection deadlines, output size, input reads, item counts, request bodies, and queue sizes are bounded. Go contexts cancel only where the implementation supports cancellation. A blocked kernel or filesystem call is not guaranteed to terminate at the deadline. Use healthy local filesystems for diagnostic resources and monitor process health through systemd.

The server has no per-account or per-IP application rate limit. Its 64 concurrent handler slots, deadlines, and message-size limits do not replace deployment-level availability controls. Authorized administrators can keep creating tasks and accumulating history; task and result retention is not automatic. Sustained operation and resource pressure on independent VPS instances remain to be measured.

## Audit and uses of hashing

The application records important state changes and retains approximately the most recent 100,000 events. Audit records exclude tokens, private keys, and full reports. Reads, heartbeats, and authentication failures do not have complete audit coverage. Agent journald output is an operational log, not another audit ledger.

Anyone controlling the database can alter or remove records. There is no hash chain, remote log destination, or tamper-proof history guarantee. Stronger historical evidence requires a separately protected audit destination and an operational process designed for it.

SHA-256 serves specific identification and comparison purposes: stored high-entropy token digests, certificate/CSR public-key fingerprints, SSH key/file fingerprints, and local baseline comparison. Ordinary task transport, result acknowledgment, policy objects, and database reads do not add redundant hash layers.

## Validation scope

Tests cover authentication, roles, local policy, incorrect TLS identities, expiry, disabling, file boundaries, repeated delivery, and recovery. They verify specific behaviors rather than certify the entire system. See [Development and validation](validation.md) for recorded checks and reproduction commands. Sustained acceptance on independent VPS instances remains pending.
