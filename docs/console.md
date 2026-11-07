# Console setup and recovery

[Documentation](../README.md) · [API](console-api.md) · [UI status](web-design.md)

The Console uses an independent browser HTTPS listener in the same server process. It is disabled unless all four Console flags are supplied. CLI and Agent traffic continues to use the Fleet address.

New Linux/systemd deployments can use the [interactive Server installer](server-installation.zh-CN.md) to configure these listeners, initialize state, publish Agent binaries, and request/renew Let's Encrypt domain or public-IP certificates. It still requires the operator to configure a Google/GitHub OAuth app (or custom OIDC) and bind the first administrator in `/setup`.

## Build and database upgrade

Build the production UI, then the embedded server:

```sh
cd web
npm ci --ignore-scripts
npm run build
cd ..
go build -tags ui -o bin/server ./cmd/server
```

New `server init` deployments use server schema 103. For an existing schema 102 database, stop the old server and run the new binary with a new backup filename in a private directory:

```sh
bin/server console-migrate -config /private/argus/server.json \
  -backup /private/argus-backups/pre-console-102.db
```

Migration verifies and syncs the original snapshot, then applies additive changes in one transaction. Failures roll back the DDL and leave the backup available. Existing nodes, tokens, tasks, results and audit remain intact. A runtime state lock excludes a running new server; **stop the old binary explicitly**, since it predates that lock. Unsupported versions still fail closed. Do not edit `PRAGMA user_version`. An older binary cannot use schema 103; rollback requires the matching old binary and pre-upgrade snapshot, with the reconciliation precautions in [Operations](operations.md#database-compatibility-and-upgrades).

## HTTPS and LAN access

Use a separate browser certificate/key with a SAN matching the Console origin. The Console refuses a certificate issued by the Fleet CA. Browser trust is established through a public CA or a separate managed browser trust root; do not distribute the Fleet CA to browser clients.

```sh
bin/server run -config /private/argus/server.json \
  -console-listen 0.0.0.0:9443 \
  -console-origin https://argus.example.com:9443 \
  -console-cert /private/console/browser.pem \
  -console-key /private/console/browser-key.pem
```

The example listens on all LAN interfaces. Resolve the origin's hostname to this machine from the client. Origin is exact, without a trailing slash, and must match the registered OIDC callback. TLS is 1.3 or newer. There is no insecure HTTP mode, wildcard CORS or trusted forwarded-header shortcut. Both listener ports are bound before serving; a failure on either shuts down both. `-check` validates configuration and credentials without opening listeners. No changes to the strict Fleet `server.json` format are required.

A build without `-tags ui` still provides APIs when enabled, but the static UI responds 503.

## One-command Agent installation

Management → Agents → Add agent defaults to a short-lived curl/wget installation command, with manual enrollment available alongside it. Enable this optional workflow with both `-console-installer-dir /absolute/published-directory` and `-console-fleet-origin https://fleet.example.com:8443`. Build trusted Linux amd64/arm64 artifacts using `sh deploy/linux/build-agent-artifacts.sh NEW_DIRECTORY`; publish them as `agent-linux-amd64` / `agent-linux-arm64`, readable by the server. See [configuration, host prerequisites and recovery](agent-installation.zh-CN.md).

Installation is explicit on a new Linux/systemd host using root/sudo; the Agent service runs as `argus-agent`. The installer preserves existing installations, verifies the downloaded binary's SHA-256, embeds only the public Fleet CA and uses the default local diagnostic policy. The target must trust the Console's independent HTTPS certificate. A single-use link expires in 1–60 minutes (15 by default), and unredeemed links are invalidated by issuing-account access/session revocation or a server restart. The underlying enrollment token has the same expiry. Never log full installation URLs. Development previews generate non-routable example links.

## Google, GitHub and custom OIDC login

First-run setup supports **direct Google and GitHub login**, separately or together. Auth0 and other OIDC providers remain optional under “Other identity provider”. See the [direct-login setup guide](console-login.zh-CN.md) or the [optional Auth0 guide](console-auth0.zh-CN.md). The server owner registers the selected OAuth applications once; later visitors use the configured sign-in buttons.

Register the exact callback supplied by the Console, including its HTTPS origin and port:

| Provider | Callback path | Configuration |
| --- | --- | --- |
| Google | `/v1/console/auth/callback/google` | Web application Client ID and Secret; issuer is fixed to `https://accounts.google.com` |
| GitHub | `/v1/console/auth/callback/github` | OAuth App Client ID and Secret; authorization, token and user API endpoints are fixed |
| Auth0 / custom OIDC | `/v1/console/auth/callback` | Exact discovery issuer, Client ID and optional Secret; existing configurations keep this callback |

Each provider uses Authorization Code + S256 PKCE and a server-bound state transaction. Distinct callback paths bind the selected provider to the transaction. Google/custom OIDC verify ID token signature, issuer, audience, authorized party, expiry, issued-at and nonce with scopes `openid profile`. GitHub uses `read:user` and obtains the immutable numeric account ID from the authenticated `https://api.github.com/user` response; usernames and email addresses are not identity keys. Provider HTTP uses verified TLS, bounded responses/timeouts and no redirects. Access tokens are transient server-side values, never browser credentials.

## First administrator

Issue a 15-minute, single-use secret locally as the server/state owner:

```sh
bin/server console-bootstrap issue -config /private/argus/server.json \
  -out /private/argus/console-bootstrap.txt
```

The destination must be new, in a private directory. Only its location is printed; the secret is written with mode 0600. Read it locally and enter it at `https://argus.example.com:9443/setup`. Select one or both social providers, register their callback URLs and enter each application’s Client ID and Secret. “Bind with Google/GitHub” saves the settings and starts authentication immediately. Custom OIDC additionally requires its issuer. GitHub validates application credentials during code exchange; saving settings alone never proves an identity or creates an administrator.

The secret establishes setup authority only. A verified callback atomically binds the first Admin and permanently closes normal setup. Five invalid proof attempts lock the secret; expiration, lost setup state or server restart before binding requires a new local issue. The existing CLI `admin.token` has no Console authority.

Provider credentials are saved as mode-0600 `console-provider-<id>.json` files in the state directory, separate from SQLite. Back them up along with Console TLS and Fleet configuration. The file now contains a provider set; legacy single-OIDC files remain readable without a database migration. Older binaries cannot read a new provider-set file, so adopting the new format is not compatible with a program-only downgrade. Database backup alone does not contain the provider secret. Never put these credentials into frontend environment variables.

## Accounts and sessions

Unknown verified identities appear as pending in Management → Users & access. Admin approves a User or explicitly grants Admin. Pending records expire after seven days when another login is processed; the account table is capped at 1,000 entries. A disabled account cannot sign in. Google and GitHub identities remain separate even when their names or email addresses match. Binding an owner with one provider does not automatically authorize an account from the other provider.

Role/access edits use an expected version and explicit subject confirmation. Existing sessions are revoked immediately by a version change; the last active Admin cannot be removed. The UI disallows editing the current account. Admin role/access changes require a session created within ten minutes; sign out and sign in again if prompted. Session revocation also increments the version.

Browser sessions expire after 30 minutes idle or eight hours absolute, with at most eight sessions per account and 1,024 total session/setup/pre-login records. There are at most 128 pending OIDC transactions. Auth/setup requests have a 30/minute per-address budget; other APIs 120/minute, with bounded rate records and 24 Console request slots. These budgets are separate from Fleet's request slots. Reverse-proxy addresses are not trusted automatically.

Logout revokes the local Argus session; it does not sign the user out of Google/GitHub/Auth0. Restart clears all browser sessions, while roles and initialization persist.

## Local recovery

If the provider or owner identity is lost, use the local server account:

```sh
bin/server console-bootstrap recover -config /private/argus/server.json \
  -out /private/argus/console-recovery.txt -confirm-recovery
```

Issuing recovery immediately invalidates all existing Console sessions. Complete `/setup` with the new secret; select and configure the required sign-in methods before binding. A successful verified binding disables former Admin accounts and establishes the recovered Admin in the same transaction. Existing User records remain. Recovery is audited, cannot be invoked over HTTP, and does not change CLI credentials or Agent certificates.

If recovery expires, issue recovery again locally. Keep the private recovery secret out of URLs and command arguments.

## Observations

Live management is functional. Dashboard system/resource data comes from existing successful diagnostic tasks; dispatch `system.info` and `system.metrics` to obtain observations. There is no background collection loop in this change. Bandwidth/traffic values remain missing until a separate periodic telemetry implementation exists. Anonymous responses contain only the safe projection, never raw task data.
