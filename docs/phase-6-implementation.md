# Argus-C2 Phase 6: Administrator Authentication, CLI, and RBAC

Phase 6 adds a separate HTTPS administration listener, a network CLI, locally provisioned administrator accounts, Argon2id password verification, opaque revocable sessions, and backend role enforcement. An Admin can submit the existing four read-only task types, issue enrollment tokens, and disable nodes. ReadOnly can inspect existing data. Reading or refreshing a result never dispatches work.

Management, enrollment, and probe traffic use separate listeners. The probe listener still requires its registered client certificate; an administrator session cannot replace mTLS. A probe certificate cannot authenticate an administrator. All listeners remain restricted to literal loopback addresses while Linux deployment hardening and operational recovery are developed in Phase 7. This remains a development prototype.

## Account bootstrap and the two CLIs

`cmd/localctl` requires direct access to the private server database and is reserved for trusted local administration and recovery. `cmd/cli` is the authenticated network client and never opens that database. A ReadOnly user must not receive server filesystem access: possession of the database and local operator tools is outside the network RBAC boundary.

Use Go 1.27.1. Follow the [Phase 4 setup](phase-4-implementation.md) for development PKI, task-signing keys, enrollment, and replay state. Existing Phase 5 probe policies and resource mappings remain unchanged; see the [inspection guide](phase-5-implementation.md). Create the first administrator under the non-root server account:

```text
go run ./cmd/localctl -state .local/phase4-server -action user-add -username operator -role Admin
go run ./cmd/localctl -state .local/phase4-server -action user-add -username viewer -role ReadOnly
go run ./cmd/localctl -state .local/phase4-server -action users
```

On an interactive terminal, the password is requested without echo and confirmed when created or reset. For automation, supply a single password line through standard input. There is no password flag or environment-variable credential fallback. Do not place real passwords in shell history or command arguments. Choose a unique passphrase. New passwords require at least 15 Unicode characters, at most 256 UTF-8 bytes, and no control characters. User names are immutable lowercase ASCII identifiers of 3–32 characters, starting with a letter; subsequent characters may include digits, `_`, or `-`.

The first account must have the Admin role. No default account, default password, public registration, or network password-recovery endpoint exists. The server supports at most 32 accounts, including disabled accounts. Account names and IDs are not recycled.

Enable management explicitly by adding `-admin-listen 127.0.0.1:8445` to the existing server command. For example, after enrollment is complete:

```text
go run ./cmd/server -listen 127.0.0.1:8443 -admin-listen 127.0.0.1:8445 -cert .local/phase4-pki/server-cert.pem -key .local/phase4-pki/server-key.pem -ca .local/phase4-pki/ca.pem -state .local/phase4-server -task-signing-key .local/phase4-signing/task-private.pem
```

If enrollment is still needed, retain the separate `-enroll-listen`, `-issuer-cert`, and `-issuer-key` arguments from the earlier guide. All listeners share the configured server transport certificate in this prototype; the enrollment issuer and task-signing keys remain separate. `-admin-listen` requires persistent `-state` and is unavailable with the static registry. It does not silently enable task signing or enrollment.

Log in from another terminal:

```text
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action login -username operator
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action me
```

The session directory must be explicitly selected under a trusted local parent. Login refuses to overwrite an existing session file. On Unix, the directory must be mode 0700 and its file mode 0600. On Windows, the file is encrypted with [user-scoped DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), without machine-wide scope or interactive prompts. Treat the parent directory as locally trusted on either platform. These controls do not protect a session from a process already running as the same OS user or from an administrator of that machine.

Stored sessions are bound to the exact normalized HTTPS origin and SHA-256 digest of the manually trusted CA file. Changing either requires a fresh login. The CLI does not print its bearer token, store the password, follow redirects, use environment proxies, or offer a TLS-verification bypass. Response bodies and headers are bounded; terminal JSON output escapes control and non-ASCII characters.

## Query and submit

Use `-session .local/viewer-session` after logging in as `viewer` to exercise ReadOnly behavior. Each command below uses the management listener and explicit trust bundle:

```text
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action agents -limit 20
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action agent -agent-id REPLACE_WITH_AGENT_ID
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action tasks -after 0 -limit 20
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action task -request-id REPLACE_WITH_REQUEST_ID
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action audit -after 0 -limit 20
```

Node pages use the last returned `agent_id` as their `-after` cursor. Task and audit pages use the last returned numeric sequence. Pages contain at most 50 records. Detail queries return one existing record. An empty page means that cursor has no later records at the time of the query.

Admin-only submissions:

```text
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action submit -agent-id REPLACE_WITH_AGENT_ID -type system.info -ttl-seconds 120
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action submit -agent-id REPLACE_WITH_AGENT_ID -type ssh.audit -profile-id host
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action submit -agent-id REPLACE_WITH_AGENT_ID -type service.status -service-id ssh
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action disable -agent-id REPLACE_WITH_AGENT_ID
```

The server generates the request ID, derives `actor_id` from the authenticated account's immutable ID, and binds the node epoch and latest ready policy digest. Client-supplied actor IDs, roles, policy digests, or signatures are not accepted. Task expiry remains 1–300 seconds. A task still passes the probe's independent local policy and cannot expand resource mappings or privileges.

`-action token -ttl-seconds 300` creates a one-use enrollment token. Unlike a session token, this enrollment token is intentionally printed once to stdout so it can be piped directly into `cmd/enroll`; its lifetime is 1–900 seconds. It remains a secret. Avoid logs or intermediate files. The existing separate enrollment listener and preinstalled trust anchor are still required.

Network Admin accounts cannot create users, change roles, reset passwords, or re-enable disabled accounts in this phase. Those operations stay with the local server operator.

## Roles and HTTP surface

| Method and path | Authorization | Behavior |
| --- | --- | --- |
| POST `/api/v1/auth/login` | Password, with persistent throttling | Issue a new opaque session |
| GET `/api/v1/auth/me` | Either role | Inspect current identity |
| POST `/api/v1/auth/logout` | Either role | Revoke current session |
| POST `/api/v1/auth/revoke` | Either role | Revoke all of the current account's sessions |
| GET `/api/v1/agents`, `/api/v1/agents/{id}` | Either role | Read stored node data |
| GET `/api/v1/tasks`, `/api/v1/tasks/{id}` | Either role | Read stored assignments and results |
| GET `/api/v1/audit` | Either role | Read a bounded audit page |
| POST `/api/v1/tasks` | Admin | Queue one fixed read-only task |
| POST `/api/v1/enrollment-tokens` | Admin | Issue a one-use enrollment token |
| POST `/api/v1/agents/{id}/disable` | Admin | Disable node identity and settle outstanding assignments |

Only `Authorization: Bearer <token>` supplies a session. Query strings, cookies, client certificates, forwarded identity headers, and request-body role claims cannot substitute for it. Duplicate Authorization headers are rejected. The service ignores forwarded source-IP claims and records the actual network peer.

Login accepts only `username` and `password`. Task submissions accept only `agent_id`, `task_type`, `params`, and `ttl_seconds`. Token requests accept only `ttl_seconds`. Logout, account-wide revoke, and disable requests require `{}`. POST bodies require explicit `application/json`, positive Content-Length, no content encoding, and no transfer encoding. GET requests have no body. Only list routes accept `after` and `limit`, once each in canonical form. Ambiguous paths, duplicate fields, unknown fields, nulls, invalid Unicode, and excessive bodies are rejected.

This CLI-only API does not implement browser sessions, CORS, or cookie authentication. Requests with Origin or Cookie headers are rejected. A browser UI would require a separate browser-authentication and CSRF design. Responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

Failures use bounded stable codes: 400 `invalid_request`, 401 `unauthorized`, 403 `forbidden`, 404 `not_found`, 405 `method_not_allowed`, 409 `operation_rejected`, 429 `rate_limited`, or 503 `unavailable`. Database errors, passwords, bearer tokens, and request bodies are not reflected in errors. The CLI does not automatically replay failed writes; inspect existing tasks before submitting a new request after an ambiguous network failure.

## Passwords, session lifetime, and abuse limits

Passwords use Argon2id v19 with a fresh 16-byte salt, a 32-byte tag, 64 MiB memory, three passes, and four lanes. The parameters are fixed and versioned; stored hash text cannot request an arbitrary KDF cost. These settings follow the memory-constrained profile in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html). At most two password KDF operations run concurrently per process, with additional Go/runtime overhead beyond the KDF memory. Password checks happen outside the database write transaction.

A login first commits its rate budget and attempt audit. After the KDF, it rechecks the exact account generation, password hash, enabled state, and role in a new transaction before creating a session. A concurrent password change, role change, account disablement, or revocation cannot issue a session using an earlier credential snapshot. Unknown and disabled users follow the same KDF parameters and generic credential-failure response. Rate-limited requests do not invoke the KDF.

| Limit | Behavior |
| --- | --- |
| Login attempts | 30 globally, 10 per peer IP, and 5 per submitted user name in a 60-second window |
| Login rate storage | Persists across server restarts; at most 1,024 buckets, with expired buckets pruned |
| HTTP admission | Eight concurrent management requests and 120 requests per minute per handler; this coarse admission budget resets on restart |
| Sessions | At most eight per account and 128 overall |
| Idle expiration | 30 minutes since the last successful authorized operation |
| Absolute expiration | Eight hours after login, regardless of activity |
| Bodies and responses | Login at most 1 KiB, other requests at most 8 KiB, responses at most 4 MiB |
| Request processing | Eight-second management context within the existing HTTP and client deadlines |

Login, lockout behavior, and session limits follow the concerns described in the [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html). Limits can also deny legitimate users during abuse; this version does not claim uninterrupted availability.

Session tokens contain 256 random bits, are not JWTs, and have no client-controlled claims. Only a domain-separated SHA-256 token digest is stored on the server. Session IDs used in audit records are separate random identifiers, not bearer tokens or their digests. Each authorized action resolves the session and current role inside the same SQLite immediate transaction as its state change, activity update, and audit. A role check performed earlier in HTTP middleware is not the authorization boundary.

The server persists an authentication clock high-water mark. A wall-clock rollback greater than 30 seconds blocks authentication operations until the clock catches up; it never moves last activity backward. Expired sessions are rejected on every request and removed using their reserved audit slots. Idle activity cannot extend absolute expiry. Session handling follows the distinction between idle and absolute expiration in [OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

## Revocation, recovery, and auditing

Log out normally, or revoke all sessions belonging to the current account:

```text
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action logout
go run ./cmd/cli -server https://127.0.0.1:8445 -ca .local/phase4-pki/ca.pem -session .local/operator-session -action revoke
```

Each successful command removes the selected local session file after server revocation. An expired or already revoked session may receive 401. `go run ./cmd/cli -session .local/operator-session -action forget` explicitly removes the local file only; it does not revoke an active server session. If logout has an uncertain network outcome, preserve that distinction and use local server revocation when needed.

Trusted local account maintenance:

```text
go run ./cmd/localctl -state .local/phase4-server -action user-password -username operator
go run ./cmd/localctl -state .local/phase4-server -action user-role -username viewer -role Admin
go run ./cmd/localctl -state .local/phase4-server -action user-disable -username viewer
go run ./cmd/localctl -state .local/phase4-server -action user-revoke -username operator
go run ./cmd/localctl -state .local/phase4-server -action sessions-revoke-all
```

Password resets, role changes, and account disablement revoke all of that account's sessions atomically, including on established HTTPS connections. Local revocation also changes the credential generation so password checks already in progress cannot issue stale sessions. Disabled accounts cannot be re-enabled through these commands; create a new account after local review if access is needed again.

Server schema 2 upgrades transactionally to schema 3, preserving node enrollment, task queues, signing-key pinning, replay-related server state, and existing audit hashes. Probe schemas and credentials are unchanged. Restarting the server normally preserves unexpired sessions and login throttles. Before starting a restored server backup, use `sessions-revoke-all` against the restored state to invalidate its old sessions. This requires trusted local administration; a coherent database rollback cannot be detected reliably from that same restored database. Probe replay recovery remains governed by the earlier guide.

Authentication attempts/outcomes, role denials, account changes, successful mutations, and authorized queries have durable audit records. Repeated rate-limited logins produce a bounded limit event rather than one event per rejected packet. Malformed or unauthenticated management traffic is rejected under the coarse admission budget without an unbounded durable event per packet. Account-change events use the subject's immutable account ID in `code`; their kind identifies the action and, for role changes, the new role. Query events record page or detail scope without copying report contents.

Each live session reserves one audit slot for its terminal event. Logout, expiry, and revocation consume those slots. Account changes aggregate revocation in their own audit event, allowing revocation to proceed when ordinary audit capacity is exhausted and sessions still hold reservations. Authentication success and administrative changes fail if required auditing cannot commit. Existing task-completion and node-disable reservations remain protected.

Audit records contain no passwords or authentication tokens. Full server compromise can still rewrite the database and its local chain together. There is no automated audit export/rotation or retention recovery in this phase; preserve evidence and resolve capacity through an explicit operator recovery plan before further deployment.

## Validation and remaining work

Tests cover real HTTPS login, separation from probe mTLS, backend ReadOnly denial, no task creation through reads, derived actor IDs, strict framing, extra role/actor fields, keep-alive revocation, persisted sessions and login limits, idle/absolute expiry, clock rollback, account-wide/global revocation, in-flight credential changes, audit failure rollback, reserved revocation capacity, and session caps. Client tests cover trust/origin binding, DPAPI corruption or Unix permission failures, redirects, oversized responses, untrusted certificates, and wrong hostnames. Management parsers and stored password-hash parsing have bounded fuzz targets; password hashing itself is not invoked by those fuzzers.

Repository CI builds and vets on Linux and Windows, runs the complete suite, and additionally runs the Linux race detector, native systemd query, vulnerability scan, and bounded fuzzers. The [login](../schemas/admin-login-v1.json), [session](../schemas/admin-session-v1.json), [identity](../schemas/admin-user-v1.json), and [task submission](../schemas/admin-task-request-v1.json) schemas describe this API's fixed shapes.

Optional TOTP/MFA, browser authentication, remote account management, credential-store integration beyond the implemented session file, public listeners, certificate renewal, and production backup/retention tooling are not implemented. There is no claimed MFA protection or alternate MFA-bypass login path. Phase 7 focuses on Linux service hardening, installation permissions, resource controls, and recovery/security exercises before real VPS deployment.
