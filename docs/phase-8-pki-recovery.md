# Argus-C2 Phase 8: Operational PKI and Local Recovery

This increment adds offline root provisioning, constrained server/issuer issuance,
local certificate and signer health reports, and recovery exercises. It complements
[client renewal](phase-8-implementation.md) and [signer rotation](phase-8-signer-rotation.md).
All listeners remain loopback-only. These tools qualify a local lifecycle; they
do not constitute a production multi-host release or independent security review.

## Authority and certificate profiles

The root private key belongs on a separately controlled offline signing host.
The application server receives only its transport key, its client-issuing key,
and the independent task-signing key. Each key is generated for one role.
The runtime never loads the root key or installs trust on another machine.

| Profile | Default lifetime | Limits and authority |
| --- | --- | --- |
| Offline root | 1,825 days | Ed25519 self-signed CA, path length 1; lifetime 1–3,650 days |
| Client issuer | 365 days | Ed25519 intermediate CA, path length 0, clientAuth only; lifetime 1 hour–365 days |
| Server leaf | 90 days | Ed25519 non-CA, serverAuth only; lifetime 1 hour–90 days |
| Client leaf | Existing server default: 12 hours | Explicit setting `-certificate-lifetime 720h` selects 30 days; supported range 1–720 hours |

Issuance is capped by the chain's expiry. All explicit durations must be whole
seconds. The issuer cannot authenticate a server or create another subordinate
CA. The server profile has only `localhost`, `127.0.0.1`, and `::1` as names.
There is no arbitrary SAN option or public-listener change in this increment.

Offline issuance accepts only a bounded, empty-subject Ed25519 CSR with valid
proof of possession and no requested attributes/extensions. It issues only the
two fixed server/issuer profiles. Client identity still comes from enrollment
and the live registry; offline tooling cannot register a node.

## Prepare and issue

Build `cmd/pkictl` with the repository's Go 1.27.2 baseline and review the binary
before installing it in the existing root-controlled executable directory.
The examples below use `pkictl` on PATH and private working directories selected
by a trusted local operator. They are preparation commands, not an installer.

On the offline host, in a private parent directory:

```sh
umask 077
pkictl -action root -out root-1
pkictl -action inspect -profile root \
  -cert root-1/root-cert.pem -ca root-1/root-cert.pem \
  -key root-1/root-key.pem
```

The output contains `root-key.pem`, `root-cert.pem`, and `receipt.json`.
Keep the private key offline with a separately protected recovery copy.
The key is unencrypted PKCS#8: the tool does not supply passphrase encryption,
an HSM, or a secret backup system. Use suitable storage protection for the
offline host and its backup. Never place this directory on the application
server or in Git.

On the future server/issuer host, in a private staging parent:

```sh
umask 077
pkictl -action request -out server-request-1
pkictl -action request -out issuer-request-1
```

Each directory contains `key.pem` and `request.pem`. Keep each private key on
its eventual host. Transfer only the two public requests to the offline signer
through the approved administrative channel, verifying their origin independently.
On the offline host:

```sh
pkictl -action issue -profile server \
  -root-cert root-1/root-cert.pem -root-key root-1/root-key.pem \
  -csr server-request-1/request.pem -out server-issued-1

pkictl -action issue -profile issuer \
  -root-cert root-1/root-cert.pem -root-key root-1/root-key.pem \
  -csr issuer-request-1/request.pem -out issuer-issued-1
```

Return only the issued `certificate.pem`, its `receipt.json`, and the independently
verified public root certificate. Receipts record the profile, root/CSR/certificate/
public-key SHA-256 values, and validity times. A receipt is unsigned review metadata;
it does not independently authenticate a transferred certificate.

On the online staging host, with the reviewed root at `root-cert.pem`:

```sh
pkictl -action inspect -profile server \
  -cert server-issued-1/certificate.pem -key server-request-1/key.pem \
  -ca root-cert.pem -server-name 127.0.0.1

pkictl -action inspect -profile issuer \
  -cert issuer-issued-1/certificate.pem -key issuer-request-1/key.pem \
  -ca root-cert.pem
```

`root`, `request`, and `issue` require a new output directory and refuse an existing
one. On Unix, directories are 0700 and files 0600; Windows operators must supply
appropriate directory ACLs. Files are synced before success; Unix directory entries
are also synced. Partial failures leave evidence in the new directory. Inspect it
locally and prepare a new generation, rather than overwriting a partial bundle.
Commands reject flags belonging to another action.

## Local installation and renewal

Follow the ownership and stopped-service installation rules in
[Phase 7](phase-7-implementation.md). Install the public root in both roles'
`ca.pem`, the server certificate at `server/server-cert.pem`, the issuer at
`server/issuer-cert.pem`, and their matching private keys in the existing
root-only `server/secrets/` paths. Public installed files are root:root 0644;
private files are root:root 0600 beneath a 0700 secrets directory.
The root private key is never an installed service credential.

Keep the separate task key and existing probe identity/policy/replay state.
Configure issuance explicitly using the reviewed enrollment or renewal override;
add `-certificate-lifetime 720h` if the local lifecycle calls for 30-day client
leaves. The application default remains 12 hours. Do not combine conflicting
`ExecStart` overrides or change the unit's hardening to activate issuance.

Only start the service after complete matching pairs and the reviewed public trust
are installed. systemd loads private credentials for that new process. Verify the
merged unit, a fresh authenticated connection, task readiness, and an allowed task.
Use the separate client-renewal procedure for each probe; the PKI tool cannot
replace its active certificate or initialize replay state.

## Health snapshots

These examples require only public configuration and may run as the relevant
service user. Private-key matching is optional and happens only with `-key`.

```sh
pkictl -action inspect -profile server \
  -cert /etc/argus-c2/server/server-cert.pem \
  -ca /etc/argus-c2/server/ca.pem -server-name 127.0.0.1

pkictl -action inspect -profile issuer \
  -cert /etc/argus-c2/server/issuer-cert.pem -ca /etc/argus-c2/server/ca.pem

pkictl -action inspect -profile client \
  -cert /etc/argus-c2/probe/probe-cert.pem -ca /etc/argus-c2/probe/ca.pem \
  -identity /etc/argus-c2/probe/identity.json

signctl -action inspect -current /etc/argus-c2/server/task-trust.json \
  -selected-key-id "$SELECTED_KEY_ID"
```

Obtain the expected selected signer from `localctl -action signers` under the
server account. Without `-selected-key-id`, the report checks for at least one
active local key; it cannot establish the running server's selection.
Legacy PEM signer trust has no expiry and reports `warning` / `no_expiry`.

Both inspection commands emit version-1 JSON and use:

| Exit code | Meaning |
| --- | --- |
| 0 | Snapshot is `ok` |
| 2 | Snapshot is `warning` or `blocked`; inspect the JSON |
| 1 | Invalid input, inaccessible/malformed file, or another inspection error |

The default warning window is ten days; `-warn-before` accepts 0–2160 hours.
Certificate entries contain public fingerprints, Unix validity times, remaining
seconds, anchor status, and `ok`, `expiring`, `expired`, or `not_yet_valid`.
Active-chain expiry, invalid names/purpose, mismatched node identity, or an explicitly
checked mismatched private key blocks the snapshot. An expired unused anchor in a
dual-root bundle generates a warning even if the selected active chain is valid.
Signer inspection similarly reports key windows; no active key or an inactive
selected key blocks the snapshot.

No keys, session tokens, or passwords appear in the report. Inspection does not
query the registry, verify a live connection, inspect the server's in-memory
configuration, or prove host integrity. It does not schedule a notification or
perform renewal. An external operator can consume these exit codes under a
separately configured monitoring policy.

Transport clients now check the verified peer chain and presented local certificate
windows before TLS record writes and before/after record reads. A pooled connection
cannot keep sending later requests after expiry or before NotBefore following a
clock rollback. Server-side per-request client-chain and registry checks remain.
There is no expiry grace or CLI clock override. Requests admitted before a boundary
are not retroactively undone, and idle sockets need not close until their next I/O.

## Planned server or issuer replacement

Generate new, separate request keys and obtain reviewed fixed-profile certificates
under the still-trusted offline root. Inspect both pairs before installation.
During a local maintenance stop, preserve the old material according to the
operator's evidence policy and install the complete pairs at the existing paths.
Restart the unchanged unit and verify fresh TLS, administrator access, and a task.

Existing client leaves continue chaining through their included old issuer until
their own validity/registry cutoff. New enrollment and renewal use the newly loaded
issuer. Renew and retire old client generations through the registry as needed.
The configured root still trusts a valid old issuer; merely replacing its online
key does not revoke all certificates signed by that issuer.

## Planned root replacement

Use this overlap procedure only for planned replacement when the old authority
remains trusted:

1. Prepare a new offline root and separate new server/issuer keys and certificates.
   Verify public fingerprints through the independent administrative channel.
2. Locally install a reviewed old-plus-new public root bundle on the server,
   probes, and administrator clients. Restart affected processes so trust is
   reloaded. Bundles allow at most eight distinct CA certificates, total 64 KiB.
   There is no remote trust-distribution endpoint.
3. Stop the server, install the new matching transport and issuer pairs, restart,
   and verify access from clients with the dual bundle.
4. Renew each still-authorized old client leaf through the new issuer, activate
   the complete pair locally, verify its chain against the new root alone, and
   retire its old registry fingerprint. Preserve node ID, epoch, replay and outbox.
5. Once every required peer is ready, remove the old root locally from every
   affected bundle and restart listeners/clients to close established sessions.
   Verify rejection of old-root server and client certificates and successful
   new-root traffic. An offline probe that missed the update requires local
   recovery; do not bypass TLS verification.

The CLI session store is bound to the exact CA file digest. After changing that
file, forget the old local session and authenticate again under the verified new
bundle. A successful TLS rotation does not change task-signing trust.

## Expiry, compromise, and lost-state recovery

| Condition | Local response |
| --- | --- |
| Server leaf expired; root still trusted | Offline-sign a replacement server request, inspect and install the complete pair while stopped |
| Issuer expired; root still trusted | Replace the issuer locally; expired client chains cannot authenticate renewal and need explicit enrollment recovery |
| Root expired | Provision replacement trust independently on every peer; use overlap only while the old chain is still valid |
| Both client generations unusable | Disable the old node and use fresh explicit enrollment; do not invent a renewal grace period |
| Signer compromised or expired | Pause dispatch and follow local signer migration/retirement; each probe must receive its reviewed local trust change |
| Issuer/root or server suspected compromised | Isolate affected services, preserve evidence, disable affected nodes/revoke sessions through trusted administration, and rebuild credentials/trust from a clean environment |
| Replay missing, corrupted, or restored | Quarantine the old identity and follow Phase 7 fresh-enrollment recovery; never initialize an empty replay database for the old identity |
| Server state restored | Run restore quarantine before reopening service, revoke resurrected sessions, and reconcile nodes using the established recovery procedure |

Do not retain a suspected compromised root for a convenience overlap. Changing
certificates alone does not clean a compromised host or make its old reports
trustworthy. A CA-valid but unregistered client leaf is rejected, but a full server
compromise includes registry and audit authority. Recovery still depends on an
independent trusted administration path. Automatic recovery, remote distrust,
CRL/OCSP integration, and off-host audit evidence remain outside this implementation.

## Validation and remaining qualification

Unit tests cover constrained issuance, key/CSR separation, root lifetime caps,
no-overwrite output, malformed bundles and CSRs, and health windows/identity/name/
key failures. Deterministic real TLS tests reuse a connection before moving the
client clock to server-leaf, peer-root, local-leaf, and clock-rollback boundaries;
the server must receive no additional request body. Certificate parsing has a
bounded fuzz target.

A real mTLS integration exercise installs dual roots locally, replaces server and
issuer authority, renews a registered client idempotently, removes the old root,
and rejects stale trust, retired-root credentials and an unregistered valid leaf.
The node/epoch and cached pending result survive, with exactly one task admission.
Existing renewal/signer crash, replay, revocation and audit-rollback tests continue.

The disposable Ubuntu fixture uses operational issuance, checks 30-day client
lifetime and public health reports, confirms root-key inaccessibility to service
accounts, replaces online server/issuer pairs under unchanged service units, and
continues through cold restore quarantine and missing-replay/fresh-enrollment
exercises. Its single VM emulates offline preparation; it does not prove physical
air-gap isolation. The sole probe `RestrictSUIDSGID=false` exception and the SSH
`openat2` reader remain unchanged.

Linux/Windows tests, Linux race checks, vulnerability scanning and fuzz smoke tests
are required for this increment. Multi-host/offline-fleet recovery drills, external
PKI/secret-storage integration, long-term capacity/retention, unattended credential
installation, and independent security review remain further qualification work.
