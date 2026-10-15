# Argus-C2 Phase 8, First Increment: TLS Credential Renewal

This guide covers client-certificate generations, authenticated and idempotent renewal, local credential inspection/revocation, and operator-assisted activation. Local task-signing-key rotation is implemented separately in the [signer rotation guide](phase-8-signer-rotation.md). Operational CA provisioning, expiry health reporting and full compromise-recovery qualification remain pending. All listeners remain loopback-only. The four task types, root-controlled policy, SSH `openat2` reader and Phase 7 unit hardening remain unchanged.

The pinned build toolchain is Go 1.27.2. This patch release includes standard-library security fixes; see the [official release history](https://go.dev/doc/devel/release#go1.27.2). The previous 1.27.1 baseline failed the current vulnerability scan.

## Identity and storage

Server schema 4 migrates each existing exact leaf fingerprint into generation 1. The node ID and enrollment epoch, task bytes, results, sessions, signer pin, audit prefix and reservations are preserved. Older databases did not retain certificates, so unknown legacy issuer/serial/key/validity metadata is shown as empty strings or zero; the original exact fingerprint remains mandatory. A successful authenticated renewal populates that generation's metadata from the verified peer chain. New enrollments store full metadata immediately.

The registry records the leaf fingerprint, node, epoch, generation, issuer-certificate fingerprint, issuer-scoped serial, public-key digest, validity, retirement cutoff and revocation. Node disablement and restore quarantine cover every generation through the live node record. Normal renewal does not change probe schemas or initialize replay state.

The current bounds are:

| Setting | Implemented limit |
| --- | --- |
| Client leaf lifetime | Explicit server setting from 1 hour to 30 days; default 12 hours |
| Chain lifetime | Issuance is capped at the earliest expiry in the configured issuer's verified chain |
| Old/new overlap | At most 24 hours and never beyond either leaf's expiry |
| Usable generations | At most two; only the newest can initiate another renewal |
| Renewal frequency | After generation 1, at least one hour between successful new issuances |
| Retained generations | At most 64 per node, including revoked and expired history |
| Request/response | At most 16 KiB each; Ed25519 CSR DER at most 2 KiB |
| Handler admission | Four concurrent requests, 30 attempts/minute per server process |

Generation and audit history are not automatically deleted. At capacity, issuance fails; do not edit SQLite tables or clear history to resume it. The HTTP admission budget is process-local, while generation/frequency/overlap constraints persist across restarts. This is a bounded local lifecycle baseline, not an indefinite retention solution.

The development CA still expires after 24 hours. Setting a longer leaf lifetime does not extend that CA, make the development PKI operational, or add renewal of the root, issuer or server TLS leaf.

## Server configuration and protocol

Renewal is disabled by default. With persistent `-state`, explicitly enable it using `-enable-renewal` and the separate `-issuer-cert`/`-issuer-key` credentials. `-certificate-lifetime 12h` is the default; any other value also requires explicit issuance enablement. The issuer, server transport and task-signing keys must remain distinct.

The existing mTLS probe listener exposes `POST /api/v1/agent/certificate/renew` only when enabled. The enrollment listener does not provide this route. Enrollment can remain closed throughout renewal.

The request contains only version 1, a random `renewal_id` and a canonical Base64URL CSR. The server derives node identity from mTLS, accepts only an empty-subject Ed25519 CSR with valid proof of possession, and never copies requested names, extensions or CA authority. Every request checks current chain validity and registry authorization. Heartbeat, task polling, result submission and issuance additionally check live credential state inside their database transactions.

The issuance transaction serializes new issuance against node disablement, certificate revocation and competing renewals. It commits the exact response, registered new credential, old-credential cutoff and issuance audit together. Failure returns no usable success response. An identical authorized retry retrieves that same response, without another certificate or issuance event. Another CSR under the same ID fails. A revoked/expired/retired authorizing credential, a disabled node, or an unusable replacement cannot use retrieval to bypass authorization.

The response binds the request, old fingerprint, node, epoch, new generation and old-credential cutoff. The client verifies its staged key against the CSR and returned certificate, verifies the pinned CA chain and constrained certificate purpose/lifetime, and rejects unexpected response fields. Responses cannot install roots, policy, arbitrary paths or another server destination.

For the Phase 7 layout, `deploy/linux/renewal.conf.example` adds renewal on the existing mTLS listener while enrollment stays closed. Install it as the sole issuance `ExecStart` override, replacing the temporary enrollment override during a reviewed maintenance stop. Do not stack the two examples: both replace `ExecStart`. If a local test needs both endpoints, explicitly add `-enable-renewal` to its enrollment configuration. Inspect the merged unit and restart after any change. No hardening override is required.

## Stage a replacement credential

Build `cmd/renew` with the same pinned toolchain as the other commands. The utility runs as the non-root probe account and has three actions:

1. `prepare`: create a new private directory, generate a new private key locally, and durably save a renewal ID/CSR bound to the current node, leaf fingerprint, server origin and CA-file digest. No network request is made.
2. `request`: authenticate with the old credential and submit the saved request. Retrying this action uses the same key and request. Verified output is saved through temporary files; `identity.json` is the final completion marker. Existing output must match byte-for-byte.
3. `verify`: connect with explicitly selected certificate/key files and confirm the live server accepts the same node identity. This verifies connectivity, not installation or task readiness.

For private development directories accessible to the non-root operator:

```sh
go run ./cmd/renew -action prepare -server https://127.0.0.1:8443 \
  -ca .local/phase4-pki/ca.pem -identity .local/phase4-probe/identity.json \
  -cert .local/phase4-probe/probe-cert.pem -key .local/phase4-probe/probe-key.pem \
  -out .local/renewal-1

go run ./cmd/renew -action request -server https://127.0.0.1:8443 \
  -ca .local/phase4-pki/ca.pem -identity .local/phase4-probe/identity.json \
  -cert .local/phase4-probe/probe-cert.pem -key .local/phase4-probe/probe-key.pem \
  -out .local/renewal-1

go run ./cmd/renew -action verify -server https://127.0.0.1:8443 \
  -ca .local/phase4-pki/ca.pem -identity .local/renewal-1/identity.json \
  -cert .local/renewal-1/probe-cert.pem -key .local/renewal-1/probe-key.pem
```

The staging directory must be private and its parent operator-controlled. `renewal.json` binds the server origin and the exact CA-file bytes: changing even the CA file's formatting requires local review, not an automatic retry adjustment. The process lock in that directory is unrelated to the active probe replay database. A partial `prepare` directory is evidence of an incomplete local preparation and is not automatically repaired. Since prepare performs no issuance, the operator can preserve it and choose a new directory. After an ambiguous request outcome, retain the existing complete prepared directory and retry `request` while the old credential is still usable; do not silently generate another request.

## Activate under the hardened Linux layout

The application does not acquire write access to `/etc/argus-c2`. A trusted administrator supplies the existing key to maintenance commands through systemd credentials. For example, run this as root on a reviewed local installation; the spawned executable runs as `argus-probe`:

```sh
systemd-run --quiet --wait --pipe --collect --expand-environment=yes \
  -p User=argus-probe -p Group=argus-probe -p UMask=0077 \
  -p NoNewPrivileges=yes -p 'CapabilityBoundingSet=' \
  -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
  -p RestrictSUIDSGID=yes -p ReadWritePaths=/var/lib/argus-c2-probe \
  -p LoadCredential=probe-key:/etc/argus-c2/probe/secrets/probe-key.pem \
  /usr/local/libexec/argus-c2/renew -action prepare \
  -server https://127.0.0.1:8443 -ca /etc/argus-c2/probe/ca.pem \
  -identity /etc/argus-c2/probe/identity.json \
  -cert /etc/argus-c2/probe/probe-cert.pem -key '${CREDENTIALS_DIRECTORY}/probe-key' \
  -out /var/lib/argus-c2-probe/renewal-1
```

Run the same command with `-action request` and the same staging directory. Keep the single quotes around the credential path so the invoking shell does not expand it; the service manager expands its own `CREDENTIALS_DIRECTORY` as documented for [systemd-run 255](https://github.com/systemd/systemd/blob/v255/man/systemd-run.xml). `%d` remains appropriate in installed unit files, but is not expanded in transient command arguments. The transient maintenance service keeps `RestrictSUIDSGID=yes`: it does not perform SSH-file inspection. The existing probe service alone retains its previously approved `RestrictSUIDSGID=false` exception.

After successful request and verification, inspect the response and locally activate the complete pair:

1. Preserve the old certificate/key and staging evidence in a separately controlled private location. Stop `argus-c2-probe.service` before touching its active pair.
2. Install the new certificate at `/etc/argus-c2/probe/probe-cert.pem` as root:root 0644 and the new private key at `/etc/argus-c2/probe/secrets/probe-key.pem` as root:root 0600. Keep the secrets directory root:root 0700. Install both while the service is stopped. Keep the existing identity, policy, trust anchors and replay directory unchanged.
3. Start the existing unit. A mismatched key/certificate fails startup. systemd reloads the credential for the new process; overwriting the source key alone does not update a running process. Verify a fresh ready heartbeat and completion of an allowed task.
4. Use server-local credential inspection to verify generation 2 and explicitly revoke the old fingerprint. Preserve or remove the staging duplicate key according to the trusted operator's retention decision; the runtime service does not manage evidence deletion.

These are local installation steps, not a remote file-write API. The utility does not restart services or atomically replace the installed pair; safety depends on the maintenance stop and complete local installation. Native CI exercises this exact boundary, including a deliberately mismatched pair and the unchanged replay audit prefix.

## Inspect and retire credentials

Run as the non-root server user with direct state access:

```sh
/usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server \
  -action certificates -agent-id NODE_ID

/usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server \
  -action certificate-revoke -agent-id NODE_ID -certificate-sha256 OLD_LEAF_SHA256
```

These operations record access/revocation audit events. The list contains public fingerprints and lifecycle metadata, not keys. Revocation applies to the next application request on an established connection as well as new TLS connections. The new credential stays valid when only the old leaf is retired. Revoking all usable leaves requires explicit recovery; it does not mint a replacement or reset the epoch automatically. Node disablement blocks every generation and keeps its existing task-cancellation semantics.

Individual leaf revocation requires ordinary audit capacity and rolls back if its audit cannot commit. Whole-node disablement can still use the existing reserved node audit slot. Keep this distinction in capacity planning. Revocation does not undo tasks already admitted on a probe, nor does a successful verification prove historical reports are trustworthy after host compromise.

## Failure and recovery

| Boundary | Behavior |
| --- | --- |
| Invalid CSR or unauthorized old credential | No successful issuance |
| Issuance/audit commit fails | Registry and overlap changes roll back; no success certificate returned |
| Success response lost | Repeat the saved request with the same still-authorized old credential |
| Partial local output write | No partial completion marker; repeat request without replacing the staged key |
| Existing output differs or directory binding changed | Stop and preserve evidence for local review |
| Active installation interrupted | Keep service stopped; install a reviewed complete matching pair |
| Old leaf revoked or overlap ends | Old leaf cannot connect or retrieve issuance; use an already completed new generation or explicit local recovery |
| Root, issuer or both usable leaves expire | Connectivity blocks; use a separately reviewed trust/re-enrollment recovery procedure |
| Replay state missing or restored | Phase 7 quarantine/fresh-enrollment rules still apply; renewal is not a replay repair operation |

At present only leaf credential metadata is exposed through the local listing. Scheduled expiry notifications, server/issuer/root renewal and a production issuance tool are not implemented. Task-signing trust changes require the separate local maintenance procedure; this TLS endpoint cannot install or rotate signing trust.

## Validation

Tests cover schema-3 migration without changes to dispatched bytes or audit history; concurrent retries through separate SQLite connections; retry after restart; CSR/request conflicts; overlap and issuance limits; audit failure rollback; node disablement; pending-result delivery with the new credential; preserved probe deduplication; revocation on a real reused TLS connection; disabled renewal routes; and rejection of malicious response identity, key, root, policy and path changes. Renewal parsers have a bounded fuzz target.

The disposable native deployment job additionally runs prepare/request through `LoadCredential`, activates the new pair under unchanged units, verifies old-leaf retirement and continued collection, and then runs the existing cold-restore/fresh-enrollment exercises. Linux/Windows, race, vulnerability and the existing fuzz checks remain enabled. This evidence qualifies this increment only; it is not completion of the remaining Phase 8 work or permission to expose public listeners.
