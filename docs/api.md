# HTTP API

[Documentation](../README.md) · [CLI reference](cli.md) · [State semantics](architecture.md) · [Collector reports](collectors.md)

This page describes the current `/v1` routes. Access is HTTPS-only; the application does not treat forwarded plaintext requests as TLS. Terminate agent mTLS at the Argus server. Forwarding a client certificate in an HTTP header does not satisfy node authentication.

## Authentication and common format

- Management routes: `Authorization: Bearer <administrator token>`. Admin can query and modify; ReadOnly can only query.
- Node routes: a TLS client certificate verified against the trusted CA, with matching node identity, certificate fingerprint, validity, and active status. An administrator token cannot replace this certificate.
- Enrollment: no existing client certificate is required; submit a time-limited enrollment token and CSR in JSON.

For request bodies, `Content-Type` must be exactly `application/json`; a `charset` suffix is currently rejected. Requests must be JSON objects with the required fields. Duplicate keys, unknown top-level fields, `null`, trailing JSON, and excessive nesting are rejected. Send `{}` for an empty request object, not zero bytes or `null`. Go type validators enforce additional field constraints.

Timestamps are Unix seconds. Task states are uppercase; node states are lowercase. Successful responses normally use HTTP 200, including creation requests. Empty task polls return 204. Responses set `Cache-Control: no-store`.

## Protocol compatibility

Enrollment and every `/v1/agent/*` request require exactly one `X-Argus-Protocol-Version: 1` and `X-Argus-Agent-Version` header. The latter contains 1–128 ASCII letters, digits, `.`, `_`, `+`, or `-`, normally a development build identifier with a commit suffix when available. These headers transport `protocol_version` and `agent_version` metadata; build identifiers are observable data, not authorization claims.

The server returns `X-Argus-Protocol-Version: 1`. The agent verifies it before processing task data or acknowledgments. Unsupported/missing metadata returns HTTP 426 with `protocol_incompatible`. Checks apply to enrollment, reconnected agents, pooled connections, renewal, and old-result uploads. Incompatibility preserves local state. There is no capability negotiation or separate result-schema version.

## Management routes

| Method and path | Role | Request | Successful response |
| --- | --- | --- | --- |
| `GET /v1/health` | ReadOnly/Admin | None | `{"status":"ok"}`; checks the database connection only |
| `GET /v1/nodes?after=ID` | ReadOnly/Admin | None | Node array, at most 200 entries |
| `POST /v1/nodes/{id}/disable` | Admin | `{}` | `{}` |
| `POST /v1/enrollment-tokens` | Admin | `{"ttl_seconds":300}`, range 60–3600 | `{"token":"..."}` |
| `POST /v1/tasks` | Admin | See below; TTL 10–3600 | Created task object |
| `GET /v1/tasks?after=ID` | ReadOnly/Admin | None | Task array without results, at most 200 entries |
| `GET /v1/tasks/{id}` | ReadOnly/Admin | None | Object with `task` and `result`; `result` is omitted until one is stored |
| `GET /v1/audit?after=SEQUENCE` | ReadOnly/Admin | None | Audit array, at most 200 entries |

`nodes` and `tasks` sort by ascending random ID. Continue with the last ID from the previous page. This is neither creation-time ordering nor a stable live-update cursor. `audit` uses nonnegative numeric IDs, starting after 0 by default. Audit IDs increase monotonically, but retention can leave gaps. There are no `limit`, node-filter, task-cancellation, node-enabling, record-deletion, or remote user-management routes.

### Create a task

```json
{
  "node_id": "node-example",
  "task_type": "service.status",
  "parameters": {"service_id": "journal"},
  "ttl_seconds": 300,
  "execution_timeout_ms": 10000
}
```

`node-example` illustrates the format; supply an existing active node ID. Parameters for `system.info`, `system.metrics`, `process.list`, and `network.listeners` are `{}`. For `ssh.audit`, use `{"profile_id":"host"}`.

The server validates the fixed parameter format but does not know each node's local allowlist. A created task can still be rejected by the agent with `local_policy_denied`. There is no creation idempotency key: repeated POSTs create different tasks. After a network timeout, query state before assuming a retry refers to the same task.

### Task object

```json
{
  "id": "task-example",
  "node_id": "node-example",
  "task_type": "system.info",
  "parameters": {},
  "status": "PENDING",
  "created_at": 1793750400,
  "dispatch_expires_at": 1793750700,
  "execution_timeout_ms": 10000,
  "result_due_at": 1793750760
}
```

IDs accept 1–64 ASCII letters, digits, `_`, or `-`; generated IDs use a secure random source. `dispatch_expires_at` must be later than `created_at` by at most 3,600 seconds. `execution_timeout_ms` is required and ranges from 1 to 30,000. `result_due_at` marks the server inference deadline, not a hard result-upload cutoff; see [Time boundaries](architecture.md#time-boundaries). See [Architecture](architecture.md) for transitions and the two forms of `UNKNOWN`. Task queries trigger expiry maintenance and may therefore write to the database.

### Node object

Fields are `id`, `hostname`, `certificate_fingerprint`, `status`, `last_seen_at`, `created_at`, `certificate_expires_at`, `protocol_version`, and `agent_version`. Status is `active` or `disabled`, with no computed online/offline state. A newly enrolled node has `last_seen_at: 0` until its first heartbeat. Certificate expiry does not automatically change its database status to disabled, but requests are rejected.

Disabling rejects subsequent valid node operations, including on existing TLS connections. TLS identity and protocol checks occur in middleware; fingerprint, validity, and active-status checks occur in each business transaction. Invalid request bodies may return 400 before database authorization. Disabling stores failed results for `PENDING` tasks and unknown results for in-flight `ACCEPTED/RUNNING` tasks. Tasks already marked `UNKNOWN` by expiry do not receive a result from disabling. There is no reenable endpoint.

The health endpoint tests the server's database connection, not write capacity or node health. Interpret heartbeat recency, task execution, and diagnostic availability separately; see [Status dimensions](architecture.md#status-dimensions).

### Audit object

```json
{
  "id": 1,
  "timestamp": 1793750400,
  "actor": "admin",
  "action": "task.create",
  "node_id": "node-example",
  "task_id": "task-example",
  "status": "accepted"
}
```

Audit `status` describes the operation outcome and need not match the task-state enum. Actions currently include `enrollment.create`, `node.enroll`, `node.renew`, `node.disable`, `task.create`, `task.accept`, `task.run`, `task.expire`, `task.complete`, and `task.prune`. Pruning records `actor: local-operator` and the removed task's terminal status. Queries, heartbeats, authentication failures, and local CLI account generation do not create corresponding audit rows. This records important state changes, not every access.

History cleanup is a local server command, with no HTTP deletion route. A pruned task is absent from listings and returns 404 on inspection. Later uploads receive explicit 404 / `task_not_found`, moving the agent's retained result to `held`; they are not acknowledged or recollected. Audit IDs remain queryable subject to the existing audit capacity. See [retention](operations.md#server-history-retention).

## Enrollment and renewal

| Method and path | Request | Successful response |
| --- | --- | --- |
| `POST /v1/enroll` | `{"token":"...","hostname":"node-a","csr":"BASE64_DER"}` | `{"node_id":"...","certificate":"PEM_CERTIFICATE"}` |
| `POST /v1/agent/renew` | `{"csr":"BASE64_DER"}` over existing node mTLS | Same shape as enrollment |

The CSR is base64-encoded DER containing a P-256 public key with a valid self-signature and no caller-selected subject, extensions, or attributes. The server assigns the node ID and certificate identity. The private key is never uploaded. The first successful enrollment binds the token to the node and CSR public key. Retrying with that key before token expiry retrieves the existing identity without creating another node.

Renewal must use the same private key. If the current certificate has more than seven days remaining, the server returns it unchanged. Within the renewal window it issues a new certificate valid for 30 days by default, bounded by CA expiry. One previous fingerprint remains accepted until its original expiry to support retries after a lost response. Node disabling applies to both fingerprints.

## Node task routes

| Method and path | Request | Successful response |
| --- | --- | --- |
| `POST /v1/agent/heartbeat` | `{"hostname":"node-a"}` | `{}` |
| `POST /v1/agent/poll` | `{}` | One task, or 204 when no work is available |
| `POST /v1/agent/tasks/{id}/running` | `{}` | `{}`; repeated confirmation is allowed while already RUNNING |
| `POST /v1/agent/results` | Complete result object | `{}` |

Hostnames must be nonempty, contain no control characters, and fit within 255 bytes. Heartbeats contain neither metrics nor policy digests. Poll responses can redeliver tasks; receiving a task again is not authorization for a fresh execution.

### Result object

```json
{
  "task_id": "task-example",
  "node_id": "node-example",
  "status": "FAILED",
  "payload": {},
  "error": "local_policy_denied",
  "completed_at": 1793750410
}
```

The result must belong to a task assigned to the certificate's node. Allowed statuses are `SUCCEEDED`, `FAILED`, and `UNKNOWN`. A success has an empty `error`, and its payload is validated against the task type and resource ID. Failed/unknown payloads must be empty objects; insignificant whitespace such as `{ }` is accepted.

The complete result is limited to 65,536 bytes, its payload to 64,512 bytes, and `error` to 128 bytes without control characters. Local agent limits may be lower. `completed_at` is a positive Unix timestamp supplied by the agent, not proof of trusted server time.

The server accepts terminal results for `ACCEPTED/RUNNING/UNKNOWN` tasks that have no stored result. Results cannot be submitted directly for `PENDING` tasks. Typed comparison ignores JSON object-key order and whitespace, preserves exact integer values and array order, and includes error and completion time. Retransmitting the same result succeeds; a different terminal result cannot overwrite it. Whether an unknown outcome can later be resolved depends on whether a result row already exists.

## Sizes, timeouts, and errors

| Request type | Body limit |
| --- | --- |
| Enrollment, renewal, task creation | 8,192 bytes; CSR DER is additionally limited to 4,096 bytes |
| Heartbeat | 1,024 bytes |
| Poll, running, disable, token creation | 256 bytes |
| Result upload | 65,536 bytes |

Task `parameters` are separately limited to 256 bytes. Server limits are 16 KiB request headers, five seconds to read headers, 15 seconds to read a request, 40 seconds to write a response, and 60 seconds for idle connections. At most 64 application handlers run concurrently. Agent and CLI HTTP requests have a 40-second timeout and reject redirects.

Application errors have a body such as `{"error":"state conflict","code":"state_conflict"}`:

| Status | Typical current causes |
| --- | --- |
| 400 | Invalid Content-Type, size, top-level fields, task parameters, or CSR |
| 401 | Invalid/expired token, missing node certificate, or failed fingerprint, validity, or active-status checks |
| 403 | ReadOnly attempted a management mutation |
| 404 | Missing node/task, or an assignment not owned by the requesting node |
| 409 | Task creation on a disabled node, queue/token capacity, invalid transition, or conflicting result |
| 426 | Unsupported or missing agent protocol metadata |
| 500 | Database or other operation failure |
| 503 | No available handler concurrency slot |

Do not assume every error body is JSON. Go ServeMux returns 404/405 for unmatched routes and incorrect methods; a TLS handshake failure has no HTTP response. The CLI exposes HTTP status and a recognized error code, never arbitrary response-body text.

Result-upload business codes are `result_conflict` (409), `task_rejected` (409), `task_not_found` (404), and `result_invalid` (400). Only these explicit status/code pairs move a pending report to local operator attention. HTTP 5xx uses bounded backoff; 401/403 reports identity/authorization failure. A generic 404, `state_conflict`, unknown code, or malformed response is not proof of permanent result rejection. No response automatically deletes report contents. A changed renewal key returns 400 / `renewal_key_mismatch`.

References: [routes](../internal/api/http.go), [Go protocol validation](../internal/protocol/protocol.go), [task schema](../schemas/task.json), [result schema](../schemas/result.json). JSON Schema describes the primary structure but does not replace lifecycle, identity, local-permission, or collector-report checks in Go.
