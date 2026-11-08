# Console setup and recovery

[Documentation](../README.md) · [API](console-api.md) · [UI status](web-design.md)

The Console uses an independent browser HTTPS listener in the same server process. It is disabled unless all four Console flags are supplied. CLI and Agent traffic continues to use the Fleet address.

New Linux/systemd deployments can use the [interactive Server installer](server-installation.zh-CN.md) to configure these listeners, initialize state, publish Agent binaries, and request/renew Let's Encrypt domain or public-IP certificates. The installer creates a reusable administrator token. Enter it at `/login` to open management immediately; OAuth configuration and account linking are optional afterward.

## Build and database upgrade

Build the production UI, then the embedded server:

```sh
cd web
npm ci --ignore-scripts
npm run build
cd ..
go build -tags ui -o bin/server ./cmd/server
```

New `server init` deployments use server schema 104. For an existing schema 102 or 103 database, stop the old server and run the new binary with a new backup filename in a private directory:

```sh
bin/server console-migrate -config /private/argus/server.json \
  -backup /private/argus-backups/pre-console-102.db
```

Migration verifies and syncs the original snapshot, then applies additive changes in one transaction. Failures roll back the DDL and leave the backup available. Existing nodes, tokens, tasks, results and audit remain intact. A runtime state lock excludes a running new server; **stop the old binary explicitly**, since it predates that lock. Unsupported versions still fail closed. Do not edit `PRAGMA user_version`. An older binary cannot use schema 104; rollback requires the matching old binary and pre-upgrade snapshot, with the reconciliation precautions in [Operations](operations.md#database-compatibility-and-upgrades).

## HTTPS and LAN access

Use a separate browser certificate/key with a SAN matching the Console origin. The Console refuses a certificate issued by the Fleet CA. Browser trust is established through a public CA or a separate managed browser trust root; do not distribute the Fleet CA to browser clients.

```sh
bin/server run -config /private/argus/server.json \
  -console-listen 0.0.0.0:9443 \
  -console-origin https://argus.example.com:9443 \
  -console-cert /private/console/browser.pem \
  -console-key /private/console/browser-key.pem
```

The manual example uses unprivileged port 9443. The Server installer defaults to 443 for new installations and grants only `CAP_NET_BIND_SERVICE` through systemd; updates preserve existing ports. The example listens on all LAN interfaces. Resolve the origin's hostname to this machine from the client. Origin is exact, without a trailing slash, and must match the registered OIDC callback. TLS is 1.3 or newer. There is no insecure HTTP mode, wildcard CORS or trusted forwarded-header shortcut. Both listener ports are bound before serving; a failure on either shuts down both. `-check` validates configuration and credentials without opening listeners. No changes to the strict Fleet `server.json` format are required.

A build without `-tags ui` still provides APIs when enabled, but the static UI responds 503.

## One-command Agent installation

Management → Agents → Add agent defaults to a short-lived curl/wget installation command, with manual enrollment available alongside it. Enable this optional workflow with both `-console-installer-dir /absolute/published-directory` and `-console-fleet-origin https://fleet.example.com:8443`. Build trusted Linux amd64/arm64 artifacts using `sh deploy/linux/build-agent-artifacts.sh NEW_DIRECTORY`; publish them as `agent-linux-amd64` / `agent-linux-arm64`, readable by the server. See [configuration, host prerequisites and recovery](agent-installation.zh-CN.md).

Installation is explicit on a new Linux/systemd host using root/sudo; the Agent service runs as `argus-agent`. The installer preserves existing installations, verifies the downloaded binary's SHA-256, embeds only the public Fleet CA and uses the default local diagnostic policy. The target must trust the Console's independent HTTPS certificate. A single-use link expires in 1–60 minutes (15 by default), and unredeemed links are invalidated by issuing-account access/session revocation or a server restart. The underlying enrollment token has the same expiry. Never log full installation URLs. Development previews generate non-routable example links.

## Google, GitHub and custom OIDC login

Account settings support **optional Google and GitHub binding**, separately or together. Auth0 and other OIDC providers remain optional under “Other identity provider”. See the [direct-login setup guide](console-login.zh-CN.md) or the [optional Auth0 guide](console-auth0.zh-CN.md). The owner can use the installation token without configuring any provider. To enable optional OAuth, register the selected applications once under Account & sign-in, then bind the chosen identities to the current account.

Register the exact callback supplied by the Console, including its HTTPS origin and port:

| Provider | Callback path | Configuration |
| --- | --- | --- |
| Google | `/v1/console/auth/callback/google` | Web application Client ID and Secret; issuer is fixed to `https://accounts.google.com` |
| GitHub | `/v1/console/auth/callback/github` | OAuth App Client ID and Secret; authorization, token and user API endpoints are fixed |
| Auth0 / custom OIDC | `/v1/console/auth/callback` | Exact discovery issuer, Client ID and optional Secret; existing configurations keep this callback |

Each provider uses Authorization Code + S256 PKCE and a server-bound state transaction. Distinct callback paths bind the selected provider to the transaction. Google/custom OIDC verify ID token signature, issuer, audience, authorized party, expiry, issued-at and nonce with scopes `openid profile`. GitHub uses `read:user` and obtains the immutable numeric account ID from the authenticated `https://api.github.com/user` response; usernames and email addresses are not identity keys. Provider HTTP uses verified TLS, bounded responses/timeouts and no redirects. Access tokens are transient server-side values, never browser credentials.

## First administrator

The installer issues a reusable, random administrator token in `/etc/argus-c2/setup/console.token` (root-only, mode 0600). Enter it at `/login` or `/setup`. The first valid token login atomically creates the local Admin and activates Console; OAuth is not required. The same token can be used after logout or restart. Only its SHA-256 digest is stored in SQLite, and it is exchanged for the normal bounded browser session rather than used as an API bearer credential.

For an uninitialized manual deployment:

```sh
bin/server console-token issue -config /private/argus/server.json -out /private/argus/console.token
```

The output file must be new, in a private directory. Reissuing invalidates previous tokens and setup sessions. A still-valid unconsumed legacy bootstrap code can also enter through token login; expired or already consumed bootstrap codes cannot. The deprecated bootstrap API remains compatible, but the UI no longer requires its provider-first flow.

Account & sign-in lets an authenticated administrator save provider credentials, then any active user can bind a configured identity to their own account. Both operations require a session created within ten minutes. The OAuth flow pins the originating session, user, version, generation and provider snapshot; logout, recovery, revocation and provider edits invalidate pending bindings. A provider identity already owned by another account cannot be reassigned. OAuth binding does not automatically disable the installation token.

An Admin can explicitly disable Token login in Account & sign-in after successful OAuth login or binding within ten minutes. This permanently invalidates the token and all token-only sessions, including their in-flight mutations, while verified OAuth sessions remain valid. Provider changes must retain a linked login method. The local token file is not deleted, but its old value is unusable. Recovery requires the explicit local `console-token recover` command.

Management → Agents supports public display-name editing and deletion. Deletion requires exact-ID confirmation and recent login, revokes the registered identity, removes task/result history and consumed enrollment tokens, and preserves audit records. It does not uninstall software from the remote host. Disable remains available when history should be retained.

Provider credentials remain mode-0600 `console-provider-<id>.json` files in the state directory. Back them up along with the database and root-only token file. Credentials never return to the browser or enter frontend environment variables.

## Accounts and sessions

Unknown verified identities appear as pending in Management → Users & access. Admin approves a User or explicitly grants Admin. Pending records expire after seven days when another login is processed; the account table is capped at 1,000 entries. A disabled account cannot sign in. Google and GitHub identities can be explicitly linked to the same local account. Matching names or emails never merges accounts; unlinked identities remain pending until approved.

Role/access edits use an expected version and explicit subject confirmation. Existing sessions are revoked immediately by a version change; the last active Admin cannot be removed. The UI disallows editing the current account. Admin role/access changes require a session created within ten minutes; sign out and sign in again if prompted. Session revocation also increments the version.

Browser sessions expire after 30 minutes idle or eight hours absolute, with at most eight sessions per account and 1,024 total session/setup/pre-login records. There are at most 128 pending OIDC transactions. Auth/setup requests have a 30/minute per-address budget; other APIs 120/minute, with bounded rate records and 24 Console request slots. These budgets are separate from Fleet's request slots. Reverse-proxy addresses are not trusted automatically.

Logout revokes the local Argus session; it does not sign the user out of Google/GitHub/Auth0. Restart clears all browser sessions, while roles and initialization persist.

## Local recovery

```sh
bin/server console-token recover -config /private/argus/server.json -out /private/argus/console-recovery.token -confirm-recovery
```

Recovery immediately invalidates all browser sessions, previous login tokens and pending bindings. The next token login disables former Admin accounts and creates a new local Admin. Existing User records, provider configuration and Fleet identity remain. Recovery is local-only and audited; it is not a normal credential rotation. The legacy `console-bootstrap recover` flow remains supported for existing operators.

## Observations

With Console enabled, idle Agent polls receive `system.info` at most once per hour and `system.metrics` at most once per minute. Existing queued/in-flight work takes precedence. Failed or policy-denied collection is also rate limited; offline Agents do not accumulate monitoring work. Fleet-only servers retain manual dispatch. No policy is changed remotely.

First resource observations usually arrive within a minute; network rates require two successful samples within 120 seconds, from unchanged interfaces with nondecreasing counters. These are interval-average bit rates, not instantaneous utilization. Stale samples and observed counter resets yield null. These counter payloads have no boot identifier, so an interface reset that already exceeds the previous counters cannot be distinguished; rates are diagnostic estimates and are not billing data. Directional capacity, bandwidth percentages, traffic totals and coverage remain unavailable. Agent updates enable default-route interface selection when the local interface list is empty.

Monitoring uses normal durable tasks/results and emits audit under `console-monitor`, roughly 1,464 tasks per Agent per day. Apply [history retention](operations.md#server-history-retention) as needed. Anonymous responses contain only the safe projection, never raw task data.
