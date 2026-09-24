**Argus-C2: Phase 4 Typed Tasks, Local Policy, and Auditing**

This guide records the Phase 4 baseline and remains the enrollment/dispatch setup reference. [Phase 5](phase-5-implementation.md) adds `ssh.audit` and `service.status` through explicit version 2 local resource policy. Version 1 policy authority and digests remain unchanged.

Phase 4 connects the existing `system.info` and `system.metrics` collectors to a signed, persistent task queue. A probe pulls tasks over mTLS, checks its locally installed signing key and policy, records an execution intent before collecting, and returns a durable result. A task cannot contain a command, path, interface, deadline override, URL, or policy update. Both task types require `params: {}`.

This is still a loopback-only development prototype. `localctl` requires direct access to the private server database; its actor label is not authenticated administrator identity. Network administrator authentication and RBAC are Phase 6 work. Linux installation hardening is Phase 7 work. Read the [design](phase-1-design.md) for the target architecture and the [Phase 3 guide](phase-3-implementation.md) for enrollment and collector details.

**Implemented flow**

1. A local operator generates a dedicated Ed25519 task-signing key and distributes the public key to the probe through a trusted local channel. The server rejects reuse of its transport or active enrollment-issuer key. The database pins the task key fingerprint; changing the key is not an automatic rotation mechanism.
2. The operator explicitly initializes a new probe state directory, bound to the enrolled node ID, enrollment epoch, and task public key. Runtime startup never creates a replacement for missing replay state.
3. The probe sends a version 2 heartbeat containing its current policy digest and task state: `ready`, `paused`, or `blocked`. Version 1 telemetry-only heartbeats remain supported.
4. `localctl -action submit` requires a ready heartbeat received within five minutes. It commits the exact task payload and an audit intent before that payload can be signed. Every task includes a generated request ID, node/epoch binding, validity window, actor label, and expected local-policy digest.
5. An authenticated probe polls its own queue. On first delivery, the server signs the original payload bytes, records dispatch, and persists the envelope. Retries receive the identical envelope. Polls wait up to three seconds when no task is available.
6. The probe verifies the signature over the original bytes, strictly parses the task, checks its target, reloads local policy, and opens a transaction. It checks persistent deduplication, time, permission, quota, result capacity, and audit capacity. It commits the running intent and audit event before entering a fixed native collector.
7. The probe records the terminal result and completion audit together, then uploads the exact saved bytes. The server requires a matching assignment and live node identity, commits the result and audit, and acknowledges the SHA-256 digest of those bytes. Only that exact acknowledgment marks the local result as delivered.

The periodic heartbeat remains independently enabled by the local telemetry configuration. `allow_system_info`, `allow_system_metrics`, and `paused` control remotely requested tasks; they do not disable periodic telemetry. No task result can alter local configuration, credentials, trust anchors, or polling settings.

**Run the complete development flow**

Use Go 1.27.1 from the repository root and a non-root account on Linux. Keep generated material in ignored `.local/` paths. Use new credential and replay directories for a new test environment; the tools refuse to overwrite existing enrollment, signing, or replay state.

Create short-lived development PKI and a separate task key:

```text
go run ./cmd/devpki -enrollment -out .local/phase4-pki
go run ./cmd/devsign -out .local/phase4-signing
```

Only `task-public.pem` belongs on probes. `task-private.pem` remains with the server. The development certificate lifetimes remain 24 hours for the root/server/issuer and at most 12 hours for an enrolled probe. Certificate renewal and signing-key rotation are not implemented.

Start the server in one terminal:

```text
go run ./cmd/server -listen 127.0.0.1:8443 -enroll-listen 127.0.0.1:8444 -cert .local/phase4-pki/server-cert.pem -key .local/phase4-pki/server-key.pem -ca .local/phase4-pki/ca.pem -issuer-cert .local/phase4-pki/issuer-cert.pem -issuer-key .local/phase4-pki/issuer-key.pem -state .local/phase4-server -task-signing-key .local/phase4-signing/task-private.pem
```

The task endpoints exist only when `-task-signing-key` is explicitly enabled with persistent `-state`. After enrollment, the issuer flags and enrollment listener can be omitted. Static-registry mode remains an identity check without dispatch.

In another terminal, enroll without placing the token in command-line arguments or shell history.

PowerShell:

```powershell
$enrollmentToken = go run ./cmd/localctl -state .local/phase4-server -action token
if ($LASTEXITCODE -ne 0) { throw 'Token creation failed' }
try {
    $enrollmentToken | go run ./cmd/enroll -server https://127.0.0.1:8444 -ca .local/phase4-pki/ca.pem -out .local/phase4-probe
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed; inspect state before retrying' }
} finally {
    $enrollmentToken = $null
}
Copy-Item examples/task-policy.json .local/phase4-policy.json
```

POSIX shell:

```sh
go run ./cmd/localctl -state .local/phase4-server -action token |
  go run ./cmd/enroll -server https://127.0.0.1:8444 -ca .local/phase4-pki/ca.pem -out .local/phase4-probe
cp examples/task-policy.json .local/phase4-policy.json
```

Review the copied policy. It explicitly allows both task types and selects only the root filesystem and loopback interface for disk/network reporting. Adjust resources locally before proceeding. Keep the policy, public key, executable, and their parent directories under trusted local administration.

Initialize replay state once:

```text
go run ./cmd/probectl -action init -state .local/phase4-replay -identity .local/phase4-probe/identity.json -task-public-key .local/phase4-signing/task-public.pem
```

Run the probe in another terminal:

```text
go run ./cmd/agent -server https://127.0.0.1:8443 -cert .local/phase4-probe/probe-cert.pem -key .local/phase4-probe/probe-key.pem -ca .local/phase4-pki/ca.pem -identity .local/phase4-probe/identity.json -policy .local/phase4-policy.json -task-state .local/phase4-replay -task-public-key .local/phase4-signing/task-public.pem
```

`-policy` replaces `-config`. Without either, the original one-shot identity check still works. Add `-once` for one heartbeat/task cycle; it flushes one pending result and may collect one task. A blocked task state produces a nonzero exit status in this mode after attempting telemetry. Allow at least five seconds between separate `-once` runs because heartbeat writes have a minimum interval.

Inspect readiness, then substitute the enrolled ID:

```text
go run ./cmd/localctl -state .local/phase4-server -action nodes
go run ./cmd/localctl -state .local/phase4-server -action submit -agent-id REPLACE_WITH_AGENT_ID -type system.info -actor-id local-operator -task-ttl 2m
go run ./cmd/localctl -state .local/phase4-server -action submit -agent-id REPLACE_WITH_AGENT_ID -type system.metrics -actor-id local-operator -task-ttl 2m
go run ./cmd/localctl -state .local/phase4-server -action tasks -after 0 -limit 100
```

The returned task page includes each task's sequence, original payload, state, terminal code, and result when available. `-after` is an exclusive sequence cursor; page sizes are 1–200. Task results contain only the requested collector's data. Windows development builds report unavailable measurements explicitly; they do not substitute fabricated Linux measurements.

Read both audit chains:

```text
go run ./cmd/localctl -state .local/phase4-server -action audit -after 0 -limit 100
go run ./cmd/probectl -state .local/phase4-replay -action audit -after 0 -limit 100
```

To pause new tasks, set `paused` to `true` in the local policy using a complete atomic file replacement. The probe reloads policy each cycle and immediately before accepting a task. Existing accepted work finishes under its recorded policy snapshot; cached results can still be delivered. Invalid policy stops the loop rather than falling back to permissive defaults. To disable the server identity entirely:

```text
go run ./cmd/localctl -state .local/phase4-server -action disable -agent-id REPLACE_WITH_AGENT_ID
```

Disablement rejects subsequent requests, including requests on an existing mTLS connection. Queued tasks become rejected; dispatched tasks without results become indeterminate. A task already delivered to a probe is not remotely cancelled. Local pause or process shutdown controls that probe.

**Local policy and resource limits**

The [example policy](../examples/task-policy.json) is explicit and strictly parsed. Missing, unknown, duplicate, differently cased, and null fields are rejected, including nested telemetry fields. The SHA-256 policy digest covers every authority and scheduling setting using a fixed domain and deterministic JSON encoding; disk/interface arrays are sorted for hashing without changing the local collection order.

| Setting | Enforced behavior |
| --- | --- |
| `allow_system_info`, `allow_system_metrics` | Explicit permission for each fixed remote task type |
| `paused` | Stops new remote task execution; telemetry and durable result delivery continue |
| `poll_seconds` | 5–60 seconds between cycles with local jitter; server responses cannot override it |
| `timeout_seconds` | 1–30 seconds; execution also respects the signed expiry time |
| `max_per_minute` | 1–30 admitted executions in a persistent sliding 60-second window |
| `burst` | 1–5 admitted executions in a sliding one-second window, no higher than the minute limit |
| `max_result_bytes` | 1,024–16,384 bytes including the result envelope; excess becomes a small `result_limit` failure |
| `pending_bytes` | At least one maximum result and at most 32 MiB; new acceptance reserves room for a full result |
| `telemetry` | Local interval, CPU sample window, disk paths, and network interfaces; unchanged Phase 3 bounds |

Execution concurrency is one. An OS file lock prevents a second process from opening the same replay database as a worker. A slow native collector is never abandoned in a goroutine while another task starts. Fixed proc reads and local allowlist counts bound collection volume. A Go context cannot reliably interrupt a blocked kernel `statfs` call; select known local filesystems. A stalled filesystem can delay both tasks and telemetry in the single loop. Process isolation and systemd resource enforcement remain Phase 7 work.

Signed task payloads are at most 8 KiB, envelopes at most 16 KiB, and task lifetimes at most five minutes. A newly received task more than thirty seconds ahead of the probe clock is rejected; an expired task never starts. The server caps submitted results at 32 KiB even though the shared protocol's future upper ceiling is 256 KiB. Heartbeats remain at most 16 KiB. HTTP client timeouts, no redirects, no automatic proxies or decompression, TLS 1.3, and live certificate authorization apply to task traffic too.

The server keeps at most 10,000 task rows and ten unresolved queued/dispatched tasks per node. It does not automatically purge task history. An undispatched expired task becomes terminal when that node next polls or receives a new submission. A dispatched expired task stops being delivered but remains unresolved, retaining its audit reservation and queue slot so a late durable result can be accepted. A result is accepted once; only byte-identical retransmission is idempotent. Results authenticate the reporting node, not the truth of its observations.

The probe keeps at most 8,192 replay/result rows. Delivered terminal records may be pruned only after signed expiry plus 24 hours. Undelivered and indeterminate records are never automatically pruned. Audit decision records remain and also prevent reuse of an accepted/rejected request ID. No operator-facing command clears deduplication state.

**Persistence, failures, and recovery**

Server schema 1 upgrades transactionally to schema 2, preserving node identities, disablement, tokens, and the latest heartbeat. Existing nodes receive a reserved audit slot for disablement. Probe schema 1 is a separate database initialized only by `probectl`. Unknown versions, mismatched identities or signing keys, invalid audit chains, and inconsistent audit reservations fail closed. SQLite uses WAL and full synchronous commits; storage durability still depends on the filesystem and device honoring those operations.

Before execution, a single transaction writes the original signed payload digest, target, policy digest, timestamps, execution intent, and audit decision. A commit or audit-write failure prevents the collector from starting. A completion-write failure leaves the running intent intact. On the next successful worker startup, every interrupted intent becomes `indeterminate` with `recovered_after_restart`; it is not automatically executed again. This is durable at-most-once admission, not exactly-once delivery or a claim that a crashed task definitely did or did not collect data.

The same request ID with different signed bytes is rejected even when the decoded fields are equivalent. A duplicate with identical bytes returns its saved result, including after expiration or a local policy change. It does not invoke the collector. A terminal result remains pending until its node, epoch, request ID, and result digest all match the server acknowledgment. Retrying after a server restart or a lost acknowledgment is safe.

The probe persists its highest observed wall-clock second. A rollback exceeding thirty seconds latches a task block that survives restart and remains after the clock is corrected. Missing/corrupt state, a held process lock, key/identity mismatch, or a rollback detected at startup leaves the agent in telemetry-only mode with `task_state: blocked`. Capacity failures at runtime also stop new tasks; previously stored results can still be attempted. If startup cannot open task state, it cannot access the outbox either. Invalid credentials or local policy remain startup errors.

If replay state is lost or its history is uncertain, stop the worker, preserve available state and audit evidence, disable the old node on the server, and perform explicit fresh enrollment into new credential and replay directories. Do not initialize empty state for an existing active identity, restore an old replay snapshot as if it were current, or delete database rows to resume execution. Software cannot distinguish a maliciously restored coherent database snapshot from genuine history without an external monotonic authority. Automated recovery, key rotation, and retention/export tooling are not implemented.

**Audit semantics**

Audit events are stored separately on server and probe. Events record operation, node/epoch, request ID, task type, actor label, source, status, code, policy digest, and relevant payload/result hashes. They do not include enrollment tokens, passwords, private keys, or raw task-result data. Server network sources use the socket peer IP and ignore forwarded headers. Probe task sources use its locally configured server origin.

The server records token creation, enrollment, signer configuration, node disablement, task intent/dispatch/expiry/cancellation, result receipt, and successful node/task/audit queries. The probe records initialization, local policy changes, invalid signed frames, request conflicts, acceptance/rejection, completion/recovery, clock rollback, and successful audit queries. Heartbeats, empty polls, exact retransmissions, and raw unauthenticated HTTP failures are not individually audited. This phase does not claim complete administrator login/authentication auditing.

Each event is SHA-256 chained to the preceding event; the head and event are committed with the corresponding state transition. A maximum of 100,000 events is retained per database, without automatic rotation or deletion. Task acceptance/queueing reserves the events needed to complete it, and enabled server identities reserve an event for disablement. Ordinary audit reads cannot consume those reservations. Once unreserved capacity is exhausted, new audited operations and audited queries fail; preserving/exporting a consistent database through trusted local administration is then necessary. Capacity should be monitored before this point.

Audit queries verify the chain, return a bounded page plus the current head sequence/hash, and append their own access event. Retain checkpoints outside the machine to make comparisons useful. A local hash chain detects inconsistent edits or missing entries relative to its retained head; an attacker controlling the whole database can rewrite the chain and head together. Full database rollback or root compromise is outside this guarantee. No external anchoring service or append-only filesystem enforcement is provided.

**Validation**

```text
go build ./...
go vet ./...
go test ./... -count=1
go test -race ./... -count=1
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go test ./internal/protocol -run '^$' -fuzz '^FuzzDecodeResult$' -fuzztime=10s -parallel=2
```

The race detector runs in Linux CI. Tests cover real enrollment/mTLS task delivery for both native collectors, exact retransmission, server and probe restarts, concurrent duplicates, interrupted execution, persistent rate limits, lost/mismatched state, local pause and policy reload, forged/unknown task parameters signed by the real server key, expiry, audit tampering, audit write failures before and after collection, reserved capacity accounting, pending-result limits, deadline handling, wrong result acknowledgments, cross-node result submission, schema migration, and live disablement. CI runs Linux and Windows builds/tests, static checks, the Linux race detector, vulnerability scanning, and parser/signature/CSR fuzz smoke tests.

The next phase adds narrowly scoped SSH configuration/authorized-key auditing and service status. Those tasks require new local resource rules and independent validation; they are not implicitly authorized by Phase 4's task pipeline.
