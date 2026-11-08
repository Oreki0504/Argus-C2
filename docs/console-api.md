# Console API contract

[Implementation status](web-design.md) · [Existing Fleet API](api.md)

Implemented by [`internal/console`](../internal/console/), with browser validators in [`web/src/api`](../web/src/api/). Enable the independent HTTPS listener using [Console setup](console.md). No route aliases or authenticates through the CLI Bearer API. Development MSW fixtures are separate from live data.

## Anonymous User browsing (revised requirement)

Visitors enter the User presentation without authentication. `GET /v1/me` may return 401; this does not create a session or grant a Web role. Anonymous reads go only to the dedicated public paths below. A rejected public request is displayed as an error; the client never falls back to a protected endpoint. Public and authenticated caches have separate prefixes. Logout clears both, then returns to the anonymous overview.

These endpoints use server-side public projections and bounded read budgets, **not a browser session**. This supersedes the original no-anonymous-Dashboard design. Existing Fleet handlers retain their authorization.

| Path | Authority / response |
| --- | --- |
| `GET /v1/console/public/summary` | Anonymous read; public summary envelope only |
| `GET /v1/console/public/nodes/{public_id}/history?range=1h` | Anonymous read; public history only |
| `GET /v1/console/nodes/{public_id}/history?range=1h` | Browser session + summary:read; same allowlisted history DTO |

All management/auth/setup authorities documented below remain unchanged. An IP-free public name and explicitly permitted system/resource/traffic fields must be selected before serialization, on every anonymous response and error as well as authenticated User responses.

## Common rules

Console origin only, HTTPS, JSON objects, Unix-second timestamps, `Cache-Control: no-store`. Writes use JSON and `X-CSRF-Token`. The backend must validate CSRF bound to the appropriate pre-login/setup/browser session **and** the exact Origin. Fetches reject redirects. Recognized error codes render safe messages; arbitrary server errors are never displayed. Writes are not automatically retried.

Status endpoints expose minimum state, with bounded sessions/body sizes/rates. `principal_id` is an opaque Web-account ID, not an OIDC subject or email. Strict public schemas detect drift; Go must prevent disclosure before serialization.

| Method / path | Authority | Behavior |
| --- | --- | --- |
| `GET /v1/console/auth/status` | None; bounded pre-login context | `{state, provider_name, providers:[{kind,name}], csrf_token, token_enabled}`; UNINITIALIZED / SETUP_PENDING / ACTIVE |
| `POST /v1/console/auth/token` | Pre-login CSRF + `{token}` | Validate the high-entropy local administrator token, activate a first owner when needed, establish session and return `/v1/me` DTO |
| `GET /v1/console/account` | Active browser session | `{csrf_token, providers:[{kind,name,issuer}], identities:[{issuer,subject,created_at}], token_enabled, can_disable_token}`; identities belong only to this account |
| `POST /v1/console/account/token/disable` | Admin + CSRF + `{confirm:true}` + successful OAuth login/binding within ten minutes under the current provider configuration | Invalidate original Token and all token-only sessions; keep OAuth sessions; return `{}` |
| `GET /v1/console/account/providers` | Admin session | Provider setup DTO without secrets |
| `POST /v1/console/account/providers` | Admin + CSRF + login within ten minutes | Save provider set; expected generation and snapshot reject stale mutations |
| `POST /v1/console/account/bind` | Active session + CSRF + login within ten minutes; `{provider}` | Start OAuth binding to this exact local account/session, fixed redirect DTO |
| `POST /v1/console/setup/prove` | Pre-login CSRF + `{secret}` | Establish setup-only session; return setup DTO; invalid/expired/consumed secret fails |
| `GET /v1/console/setup` | Setup session | Setup DTO; 401 without proof, 403 after ACTIVE |
| `POST /v1/console/setup/provider` | Setup session + CSRF | `{providers:[{kind,issuer,client_id,client_secret}]}`; one to three distinct kinds (`google`, `github`, `oidc`); native issuers are fixed; no secret echo |
| `POST /v1/console/setup/bind` | Validated setup + CSRF; `{provider:kind}` | Start first-owner authentication transaction; `{redirect_path: "/v1/console/auth/redirect"}` |
| `POST /v1/console/auth/login` | Pre-login + CSRF; `{provider:kind}` | Start normal authentication with a configured provider; same fixed redirect DTO |
| `GET /v1/console/auth/redirect` | Pending bounded OIDC transaction cookie | Top-level navigation; server redirects to its configured provider; no caller destination |
| `GET /v1/console/auth/callback` | Code/state/nonce/PKCE validation | Atomically bind first Admin or authorize existing account, establish session, redirect to fixed UI path |
| `GET /v1/console/auth/callback/google` | Bound Google transaction + PKCE + verified ID token | Direct Google binding/login; issuer and immutable subject determine identity |
| `GET /v1/console/auth/callback/github` | Bound GitHub transaction + PKCE + authenticated user API | Direct GitHub binding/login; fixed issuer and numeric user ID determine identity |
| `GET /v1/me` | Browser session + current local role | `{principal_id, name, role, csrf_token, capabilities}`; Admin/User; capabilities below |
| `POST /v1/console/auth/logout` | Browser session + CSRF; `{}` | Immediately revoke session, clear cookie, return `{}` |
| `GET /v1/console/summary` | Browser session + `summary:read` | Public summary for both roles in this iteration; server projection required |

The redirect route consumes a transaction whose authority is held on the server. Callback failures may redirect to `/login?reason=<allowlisted-code>`, never including raw provider errors, tokens or a caller return destination. The frontend accepts only the exact redirect-path literal, rejecting external URLs and query strings. Mock sign-in skips external redirects and performs no OIDC validation.

Callback diagnostics distinguish `oauth_callback_invalid`, `oauth_cookie_missing`, `oauth_flow_expired`, `oauth_state_mismatch`, `oauth_callback_mismatch`, `oauth_issuer_mismatch`, `oauth_provider_rejected`, `oauth_configuration_changed`, and `oauth_account_failed`. GitHub exchange/profile failures have separate `github_*` classifications. Validated binding transactions return failures to `/account`; no check is relaxed. Logs contain only fixed classifications, not callback queries or upstream response bodies.

Token disabling persists across restarts; the old local token file no longer grants access. `can_disable_token` indicates recent OAuth verification, not merely the presence of saved app credentials. Mutations from token-only sessions recheck revocation inside the database transaction. After disabling, provider edits must retain a provider linked to the current Admin (`last_signin_method` otherwise). Local `console-token recover` is the explicit recovery path; it replaces administrator access rather than re-enabling the old token.

Setup DTO: `{step: "provider" | "bind", csrf_token, callback_uri, issuer, client_id, providers:[{kind,name,issuer,client_id}], callback_uris:{google,github,oidc}}`. All callbacks come from the server's exact configured HTTPS origin. Legacy single-OIDC configuration requests and `{}` login bodies remain accepted; an empty login selection is valid only when exactly one provider is configured. The legacy `callback_uri` remains the custom OIDC callback. New social configurations use their distinct callback paths; callbacks cannot switch the transaction's selected provider.

A blank application Secret reuses the saved value only when provider kind, issuer and Client ID all match. Secrets never appear in the DTO. Saving settings is not identity proof; GitHub application credentials are checked during code exchange, and Google/OIDC discovery cannot validate a client secret. The UI first permits token login without any provider configuration. Authenticated account settings save providers separately from binding. Binding pins the original session, account version, generation and provider snapshot; logout, account revocation, recovery and provider changes invalidate it. Existing identities cannot be moved between accounts. Successful binding returns to `/account?bound=1`; binding failures return to `/account?reason=<allowlisted-code>`. Legacy `/setup/*` APIs remain available for compatibility, but ACTIVE closes them.

## Public summary

Envelope: `{generated_at, window_start, window_end, sample_interval_seconds, nodes}`. The UI filters this complete list locally. Live responses are bounded to 1,000 nodes; larger fleets receive 503 instead of a partial success. The 300-node fixture is a UI exercise, not a scalability claim.

```json
{
  "public_id": "srv-opaque",
  "display_name": "Production · North",
  "last_seen_at": 1794009600,
  "system": {"os": "Ubuntu 24.04", "architecture": "x86_64", "kernel": "6.8.0", "uptime_seconds": 86400},
  "resources": {"as_of": 1794009600, "cpu_percent": 24, "memory_percent": 58, "disk_percent": 36},
  "traffic": {"as_of": null, "inbound_bps": null, "outbound_bps": null, "inbound_capacity_bps": null, "outbound_capacity_bps": null, "sampled_inbound_bytes": null, "sampled_outbound_bytes": null, "coverage_percent": null}
}
```

System values and measurements may be `null`; missing differs from zero. Resource percentages are server-derived aggregates. Rates are **bits/s**, totals are **bytes measured over valid intervals in the envelope window**, never extrapolated/billing usage. Coverage refers to the same window; reset/restart/missing intervals remain unmeasured. Single aggregates cannot produce a history chart; the separate history response supplies the samples. Cards show per-agent rates with resource and traffic observation times; stale observations are explicitly labeled.

Names default to opaque `Server-<public-id-prefix>` labels. Admin can explicitly set a public display name; the UI warns against including private information. System text is reduced to known OS families, architecture names and kernel versions. No collected hostname/IP/interface/mount paths, certificates, raw tasks/results or sensitive nested data enter this projection. Admin models/routes are separate; User never fetches full Fleet payloads to hide fields afterward.

## Errors and validation

Recognized codes: `token_invalid`, `identity_conflict`, `session_expired`, `forbidden`, `bootstrap_invalid`, `setup_closed`, `oidc_unavailable`, `oidc_callback_invalid`, `account_pending`, `csrf_invalid`, `rate_limited`, `service_unavailable`. HTTP 401/403 clears or hides protected data; 503 offers explicit retry. Unknown/HTML bodies yield generic status messages, without raw diagnostics.

Go tests cover bootstrap concurrency, signed OIDC claims/replay, session/CSRF/Origin/revocation and public projection leakage. CI also validates actual Go management/summary responses against the TypeScript schemas. This does not replace provider-specific deployment testing.

## Utilization history and bandwidth baselines

**Live data is task-driven:** a Console-enabled Server now schedules `system.info` hourly and `system.metrics` every minute on idle Agent polls, subject to local policy. History uses server receipt timestamps and the latest successful observation per 60/300/900-second display bucket. Summary network rates are interval averages derived from two successful counter samples at most 120 seconds apart with identical available interface sets and nondecreasing counters. The latest receipt must also be no older than 120 seconds. Invalid, stale or decreasing pairs yield null. Capacity, traffic byte totals, coverage and historical network percentages remain null; rates alone cannot establish these. The following bandwidth-capacity rules describe the schema when configured baselines become available.

Summary traffic adds `inbound_capacity_bps` and `outbound_capacity_bps`, each a positive configured directional baseline or null. Current bandwidth percentage is rate / capacity × 100. Unknown capacity or rate means unavailable, never zero. The displayed percentage can exceed 100; only the card bar is capped to its 100% track. Actual bit rates remain visible beneath bandwidth indicators.

History ranges are `1h`, `24h`, `7d`. The history envelope contains `public_id`, `range`, `window_start`, `window_end`, `sample_interval_seconds` and at most 2000 strictly increasing `points`. Each point contains `timestamp`, `cpu_percent`, `memory_percent`, `disk_percent`, `inbound_percent`, `outbound_percent`; all five percentages are nullable. CPU/memory/disk are 0–100; bandwidth percentages may exceed 100. Historical network percentages must use the capacity configured at that timestamp, not today's capacity. Timestamps must lie inside the requested window. The client rejects mismatched node/range responses and extra nested fields.

Charts break at null values and absent sample intervals. There is no interpolation over gaps or fabricated history from current values. The displayed average is the arithmetic mean of returned measured samples, not a time-weighted window average. Returned sample counts do not claim full-window coverage. Production history comes only from the API; generated waveforms live exclusively in the development fixtures.

## Admin management

Every route below requires a current **Web Admin** session. The server does not accept a CLI Bearer or Agent certificate in its place. User receives only `summary:read`; Admin additionally receives `tasks:read/write`, `agents:read/write`, `audit:read`, `users:read/write`. Capabilities drive UI presentation; server roles and account versions are authoritative. All writes also enforce CSRF and exact Origin.

| Method / path | Body / filters | Response |
| --- | --- | --- |
| `GET /v1/console/admin/agents` | `q`, `status=active|disabled`, `public_id`, `limit`, `cursor` | Agent page |
| `POST /v1/console/admin/enrollment-tokens` | `{ttl_seconds}` (60–3600) | `{token,expires_at}`; store digest only; usable on Fleet enrollment |
| `GET /v1/console/admin/installer` | None | `{enabled,platforms,fleet_origin}`; published Linux platforms, empty when disabled |
| `POST /v1/console/admin/installations` | `{ttl_seconds}` (60–3600) | `{installation_id,url,expires_at}`; short-lived, single-use install-script URL, no raw Fleet token |
| `POST /v1/console/admin/agents/{node_id}/disable` | `{confirm_node_id}` matching path | Agent; shared disable/unfinished-task transaction |
| `POST /v1/console/admin/agents/{node_id}/rename` | `{display_name}`; trimmed, 1–64 printable Unicode characters | `{}`; update public name and audit atomically |
| `POST /v1/console/admin/agents/{node_id}/delete` | `{confirm_node_id}` matching path; login within ten minutes | `{}`; delete identity, public mapping, tasks/results and consumed enrollment tokens; retain audit |
| `GET /v1/console/admin/tasks` | `node_id`, `status`, `task_type`, `limit`, `cursor` | Task page; existing request-driven expiry applies |
| `POST /v1/console/admin/tasks` | Existing strict TaskRequest | Task; six fixed collectors only, TTL 10–3600, timeout 1–30000 ms |
| `GET /v1/console/admin/tasks/{id}` | Valid task ID | `{task,result}`; nullable result |
| `GET /v1/console/admin/audit` | Exact `action`, `node_id`, `task_id`, `subject_id`, `limit`, `cursor` | Audit page |
| `GET /v1/console/admin/users` | `q`, `status=pending|active|disabled`, `limit`, `cursor` | Account page |
| `POST /v1/console/admin/users/{id}` | `{role,status,expected_version,confirm_subject}` | Updated account; sessions revoked; self-edit and last-Admin removal refused |
| `POST /v1/console/admin/users/{id}/revoke-sessions` | `{}` | `{}`; immediately increments account version |

Pages have exactly `{items,total,next_cursor}` with a nullable cursor. Limit defaults to 8, ranges 1–200. Tasks sort by descending `(created_at,id)`; other pages by descending ID. Cursors bind to the route and filters. Listings are live, not frozen snapshots; filters may change membership between requests. Unknown/duplicate query keys and malformed bounds are rejected. Text search is literal and case-insensitive under SQLite's default LIKE behavior.

Agent DTO: `{node_id,public_id,display_name,hostname,status,last_seen_at,created_at,agent_version,protocol_version,certificate_expires_at}`. Unlike the public projection this exposes the hostname, but never certificate/private-key material. Enrolled Agents with `last_seen_at=0` remain available here for administration; public summaries omit them and their public history returns 404 until the first heartbeat.

Deletion removes the Agent from public and management listings. Its old certificates and consumed enrollment tokens cannot restore access. A new registration requires a fresh token. Deletion does not uninstall software or interrupt work already executing on the host. Use disable when history should remain, and the local uninstall command when retiring the host installation. Failed audit insertion rolls back the entire rename/delete transaction.

Task DTO extends the existing task fields with `agent_name`, nullable `execution_authorized_at` and `result_received_at`. Result DTO is `{status,error,completed_at,payload}`. Payload is the retained diagnostic JSON, available only to Admin. `ACCEPTED` means selected for delivery, not confirmed Agent receipt. `UNKNOWN` retains the existing unresolved/persisted-result semantics; it is not proof of cancellation. Writes are never automatically retried after uncertainty.

Account DTO: `{id,name,issuer,subject,role,status,created_at,last_login_at,version}`. Identity matching uses issuer + subject, never display name/email. Approval changes pending to active. Edits use optimistic version checks; Admin-related access changes require a session created within ten minutes. Revoking sessions also changes `version`, so refresh the list before editing again.

Audit DTO: `{id,timestamp,actor,action,node_id,task_id,subject_id,status}` with nullable target IDs. Browser actors use `web:<account-id>`. Existing Fleet action names are preserved; Console actions include `node.rename`, `node.delete`, `console.token.disable`, `console.user.update`, `console.sessions.revoke`, `console.login/logout`, `console.owner.bind/recover`, bootstrap/provider/migration changes. Secrets, tokens and session IDs are never audit payloads.

Additional allowlisted errors: `invalid_request`, `not_found`, `node_disabled`, `state_conflict`, `user_conflict`, `last_admin`, `self_change`, `reauthentication_required`. Storage/internal/provider failures return generic codes, not raw diagnostics. An uncertain write must be reconciled by reading current records before a new attempt.

## Installer downloads

`GET /v1/console/install/{ticket}` authenticates with an unguessable, single-use URL credential instead of a browser cookie. It returns `text/x-shellscript` with `no-store`, attachment and no-referrer headers. The ticket is bound to its issuing Admin's account version and Console generation; transactional revalidation occurs before disclosing the script. Concurrent GETs have exactly one winner. Unknown, expired, already consumed or revoked tickets receive the same 404 `installation_unavailable`. HEAD returns 405; browser navigation/prefetch returns 400 without consumption. Only command-line GET redemption is intended. Script download failure requires a new command.

Ticket digests and underlying enrollment secrets are held only in a bounded memory map (128 links); the enrollment token digest/expiry use the existing database. Server restart invalidates all links. The script's enrollment token shares the original expiry and cannot enroll a second host identity. Account revocation cannot recall an already downloaded script. Creation/redemption use `console.installation.create` and `console.installation.redeem` audit actions and a non-secret installation ID; URLs/tokens are never audit fields.

`GET|HEAD /v1/console/install/assets/{arch}/{sha256}` serves only preloaded static Linux Agent binaries for `amd64` or `arm64`, at most 32 MiB per architecture. These contain no credentials and require no browser session. The hash and architecture must match a published immutable snapshot; no caller-selected path, external URL or runtime build is accepted. Files change only on server restart. All existing Console TLS/Host, rate, request-slot and no-store rules apply. Installer creation returns 409 `installer_unavailable` when optional publication configuration is absent.
