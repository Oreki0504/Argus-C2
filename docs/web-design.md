# Web Console implementation

[Documentation](../README.md) · [Console setup](console.md) · [Console API](console-api.md) · [Frontend development](../web/README.md)

ARGUS now includes the React console, an optional independent HTTPS Console listener, reusable local administrator token login, Google/GitHub and custom OIDC login, server-side sessions, Web Admin/User authorization, and real management APIs. Console defaults to disabled. Existing CLI Bearer and Agent mTLS routes remain on the Fleet listener and keep their original authorization.

## Navigation and design

The selected **Argus Hybrid** direction combines [Geist](https://vercel.com/geist/introduction) typography and restrained surfaces with [Carbon](https://carbondesignsystem.com/) table and interaction patterns. It uses semantic HTML, local Geist fonts, static CSS and Lucide icons, rather than an official component-library implementation.

Anonymous visitors enter the public User overview. Neither User nor Admin has a sidebar. Admin's top bar contains Overview / Traffic / Management. Management has horizontal **Tasks / Agents / Audit / Users & access** navigation. The public overview keeps search and four status filter cards in one row, compact Agent cards and five aligned number/bar indicators. Filters use persistent state-colored borders when selected, with unchanged surfaces; server cards use their heartbeat color on hover/focus. Only Agents with a received heartbeat enter public summaries; pending enrollment records remain in Management. Details provide charts and system facts. Chinese/English and light/dark controls persist display preferences only.

[UI design rules](ui-design-system.md) target Overview and Details fitting 1366×768 and 1440×900 at 100% zoom. Management tables use bounded internal scrolling and pagination. Mobile, zoom and long results allow natural scrolling without clipping content.

| Page | Implemented behavior |
| --- | --- |
| Setup / sign-in | Token login opens management immediately; optional Google/GitHub or custom OIDC configuration and binding in account settings |
| Overview / details | Safe public names, heartbeat, allowlisted system/resource observations and sampled history |
| Tasks | Six fixed diagnostic collectors, typed parameter forms, TTL/timeouts, list filters, results and related audit |
| Agents | One-command Linux installation (curl/wget), manual registration token and CLI fallback, access/certificate state, public-name editing, exact-ID disable/delete confirmation |
| Audit | Action, Agent, task and account filters, stable pagination and related-task links |
| Users & access | Pending approvals, role/access edits with version checks, session revocation and last-Admin protection |

## Real data and current limits

Management uses the shared SQLite-backed Fleet services. A Console-created task is delivered through the existing Agent polling protocol; registration tokens are accepted by Fleet enrollment. Disable uses the existing transaction and unfinished-task semantics. Tasks do not accept arbitrary commands, shell scripts or policy editing. The separate opt-in installer serves a fixed, versioned shell template and operator-published Agent binaries; it runs only when explicitly pasted on a new host. See [installation configuration](agent-installation.zh-CN.md).

Public summaries use a separate Go projection. Names default to opaque `Server-<id>` placeholders and can be explicitly renamed by Admin for public display; collected hostnames, internal node IDs, IPs, interfaces, mount paths, certificates, raw results and audit never enter public responses. System strings are reduced to a small vocabulary/version representation. Missing observations remain null.

CPU, memory and disk come from successful `system.metrics` results; system information comes from `system.info`. History uses real result receipt times, selecting the latest result per 60/300/900-second display bucket. Console now schedules information hourly and metrics each minute on idle Agent polls, without overriding local policy or queued operator work. Two recent compatible network-counter samples provide interval-average bit rates. Bandwidth capacity, utilization percentages, traffic totals and coverage remain null until configured baselines and interval accounting exist. History is affected by task/result retention. Public summary currently rejects fleets larger than 1,000 nodes rather than silently truncating them. Continuous traffic accounting remains future work.

Agent deletion removes the registered identity and task/metric history, retains audit, and requires recent login plus exact-ID confirmation. It does not remotely uninstall the host. Account settings also allow an Admin with recently verified OAuth access to permanently disable the original token and revoke token-only sessions.

## Authentication and storage

Authorization Code + S256 PKCE supports Google, GitHub OAuth Apps and custom OIDC providers such as Auth0. One or both social providers can be configured after token login in account settings. GitHub verifies its stable numeric user ID through its fixed authenticated user API; Google/custom OIDC verify signed ID tokens. Each provider has a distinct callback path. Signatures/JWKS, issuer, audience, authorized party, expiry, issued-at, nonce, state and exact callback are verified. Provider `(issuer, subject)` identities map to local accounts; explicit binding attaches them to the current account, while unlinked sign-ins are pending until approved.

Sessions contain opaque random credentials whose digests are held in bounded server memory. Cookies use Secure/HttpOnly/Strict/Path=/ and no Domain; the short-lived OIDC correlation cookie uses Lax. Idle expiry is 30 minutes, absolute expiry eight hours; restart clears sessions. Writes require exact Origin plus session-bound CSRF. Account version/generation checks also run inside mutation transactions, so revoked authorization cannot race a write. Role changes revoke sessions; changes involving Admin access require a login within ten minutes.

Schema **104** preserves owner/bootstrap state, Web accounts, public IDs and audit subjects, and adds token digests and multiple provider identities per account. The explicit 102/103 → 104 migration creates and verifies a durable backup before transactional DDL. Startup never migrates implicitly. Provider credentials are separate private files and must be backed up independently. See [setup and recovery](console.md).

## Development and validation

Mock mode is explicitly marked and remains available over LAN. Production builds contain no mock worker, fixtures, preview toolbar or fallback. Live builds serve UI and API from the Console's HTTPS origin; Vite is only a preview tool.

Tests exercise signed local OIDC discovery/exchange, PKCE, invalid claims/replay, cookie/CSRF boundaries, revocation, atomic owner binding, migration rollback, real enrollment/task/result/disable flows, public projections and Go-response/TypeScript-schema compatibility. Browser tests cover UI workflows, permissions, localization, responsive layouts and accessibility. They do not claim a completed deployment-specific Google/GitHub/Auth0 app registration or a third-party security review.
