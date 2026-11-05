# Frontend preparation

[Documentation](../README.md) · [API](api.md) · [Security](security.md)

This document defines the proposed browser authentication boundary. **No frontend, browser login, cookie authentication, or session service is implemented yet.** The current CLI keeps named bearer tokens, loaded at server startup. Session implementation is deferred to the Frontend work; it must precede exposure of a browser management interface.

## Proposed session lifecycle

Use the existing HTTPS origin for the frontend and API. A login request supplies a management credential over TLS; the server verifies it and issues a cryptographically random opaque session ID. Do not place long-lived management tokens in URLs, localStorage, sessionStorage, browser-readable cookies, or frontend configuration. Clear the submitted credential from application state after the exchange and never log it.

Store only a hash of the session ID, account identity, credential generation, creation/last-use times, and absolute expiry on the server. An initial bounded in-memory store can invalidate all sessions on restart and avoid a new database component. Proposed limits are 30 minutes of inactivity and 8 hours absolute lifetime, with explicit logout/revocation; these are design defaults to confirm during Frontend implementation, not current settings. Rotate the session ID on login and privilege changes. Bound session count and rate-limit login attempts without logging submitted credentials.

Deliver the ID through a host-only `__Host-argus-session` cookie with `Secure`, `HttpOnly`, `Path=/`, and `SameSite=Strict`; omit `Domain`. For every authenticated browser request, enforce session expiry and current account/credential generation before applying Admin/ReadOnly permissions. Do not trust a role copied into browser state. Reject ambiguous requests containing conflicting bearer and session identities.

SameSite is defense in depth, not the sole CSRF defense. State-changing session requests need a session-bound CSRF token and strict Origin validation, with explicit rejection of missing/untrusted origins for browser mutations. Cover login and logout against CSRF and session fixation. Keep CORS disabled for other origins by default; never combine credentialed requests with wildcard origins. Use TLS, a restrictive CSP, and escaped UI rendering; HttpOnly does not prevent malicious scripts from making authenticated requests.

## Revocation and administration

The first implementation can retain the current account-file/restart model if it clearly states the timing: editing `admins.json` alone has no effect until restart, and restart invalidates all in-memory sessions. After reload, removed accounts and replaced tokens cannot log in again. Credential replacement must invalidate sessions derived from the old credential even if the account name is unchanged. Logout must invalidate the server record before clearing the cookie.

If runtime credential reload or targeted revocation is added, it must atomically update the effective account set and invalidate affected sessions; define a linearization point so a revoked identity cannot authorize a later mutation. A reload of systemd `LoadCredential` source files still needs a service restart under the current deployment model. Do not promise immediate token revocation from editing those sources.

Before release, tests must cover token replacement/removal, role downgrade, session expiry and logout, restart invalidation, CSRF/Origin rejection, fixation, duplicate cookies, concurrent revocation, ReadOnly mutation refusal, log redaction, and bounded session/login resources. Existing bearer-client behavior must remain tested separately. Do not add cookie acceptance without these lifecycle checks.

## Current API preparation

`GET /v1/tasks?order=newest` is implemented with node/status/time filters, a bounded page size, and a `(created_at, id)` descending cursor; see [API](api.md#newest-task-pages). Keep filtering on the server. The legacy random-ID listing remains available for existing CLI clients. Parameterized JSON media types with UTF-8 are accepted; this does not enable CORS or browser sessions.

Render [the four status dimensions](architecture.md#status-dimensions) separately. Show server receipt time alongside the agent's completion claim, preserve UNKNOWN as uncertain, and expose `available`, `coverage`, and `truncated` rather than mapping every SUCCEEDED task to a green host-health indicator. Pagination is a live view, so refresh the first page for new tasks and do not describe it as a database snapshot.

Server leaf-certificate monitoring and manual rotation are independent of session implementation. Offline Root + Online Intermediate remains a separate [PKI plan](security.md#offline-root-and-online-intermediate-plan).
