# Phase 8: Local Task-Signing-Key Rotation

This increment adds explicit local signer trust migration, bounded overlap and retirement. It preserves enrollment identity, replay history, clock state, dispatched task bytes and pending results. It does not complete Phase 8: operational CA provisioning, expiry health reporting, issuer/root replacement tooling and full compromise-recovery qualification remain pending. TLS trust, local task policy, the four read-only task types, loopback listeners, the SSH `openat2` reader and the base systemd units are unchanged.

## Protocol and trust decisions

A trust set is a root-controlled local configuration document, not a message accepted from the server. Its stable random `trust_set_id` identifies the local lifecycle; `generation` advances by exactly one per maintenance change. Keys have explicit `not_before` and exclusive `not_after` Unix-second boundaries. Each `key_id` is the lowercase SHA-256 of the raw 32-byte Ed25519 public key. There are no key URLs, delegated keys, remotely supplied roots or policy updates.

The [trust schema](../schemas/signer-trust-v1.json) permits one or two keys, at most 24 hours of positive overlap, and 64 retained retirement IDs. Retirement history is cumulative and prevents a removed key from being introduced again. Each transition retains one key, adds or removes one key, and cannot extend an existing key's validity or enable legacy signatures for another key. Capacity exhaustion requires explicit lifecycle review; it never clears trust or replay automatically.

The [v2 envelope](../schemas/envelope-v2.json) has exactly `version`, `trust_set_id`, `key_id`, `payload_b64` and `signature_b64`. Ed25519 signs these exact bytes:

```text
"argus-c2/task/v2\x00" || trust_set_id || "\x00" || key_id || "\x00" || decoded_payload
```

The two IDs have fixed canonical lengths and are covered by the signature. The task payload remains version 1, with its original bytes and existing limits. Verification occurs before task decoding and execution admission. The current local time must lie inside the selected key window, and the entire declared task interval must fit inside it. No clock-skew grace extends key authority. The probe rechecks the key window inside its replay admission transaction. Policy, target, lifetime and replay checks still apply independently.

The original two-field v1 envelope remains usable only by the original pinned key during its explicitly installed overlap. Newly added keys cannot authorize v1 envelopes. Once the old key expires or is locally removed, old-key envelopes fail, including replay deliveries of previously completed work. Their already committed results can still leave the outbox without admitting another task.

## Persistent state and concurrency

Server schema 5 adds a persistent dispatch pause and optional canonical trust document. Upgrading from schema 4 preserves the legacy signer fingerprint and every existing task/result/audit row. Ordinary server startup still cannot replace the selected signer. The server reads the current selected key and trust inside each dispatch transaction, so an old running process cannot resume signing after a local switch.

Probe schema 1 remains supported for existing PEM installations. Only `probectl trust-migrate` moves an existing probe to schema 2. The command acquires the same exclusive process lock as the worker, verifies identity, current trust binding, database integrity, audit chain, clock state and replay/result records, and atomically commits the new binding and an audit event. It does not initialize replay, clear the clock latch or recover interrupted tasks. Recover an interrupted task with the current trust before migration; the resulting indeterminate outcome is preserved.

Trust events record the previous fingerprint in `payload_digest` and the next fingerprint in `result_digest`. Initial migration uses the raw public-key digest for the old fingerprint; subsequent changes use the SHA-256 of canonical trust JSON. Retrying an already committed exact migration is a no-op. A mismatched installed file blocks task execution; it never silently changes the database binding. Probe telemetry may continue with task state `blocked`, following the existing behavior.

Dispatch pause blocks new queue admission and polling, while telemetry and already-dispatched result submission remain available. A switch requires an empty undispatched queue: drain it before maintenance, or explicitly cancel it with the local command below. Cancellation preserves original payloads and request IDs with code `signer_changed_before_dispatch`; it does not touch dispatched assignments. Submit any replacement work with a new request ID after maintenance.

Dispatched envelopes are never re-signed. During overlap, the server can redeliver the original envelope using its installed old public key while holding only the new private key. Server trust changes refuse to invalidate an unexpired dispatched envelope: deliver its result or wait for its task expiry before retirement. Expired dispatched rows retain their exact bytes and reserved late-result slot. This preserves delayed results but also retains existing storage limits; rotation is not a retention mechanism.

## Prepare local artifacts

Build `cmd/signctl` along with `server`, `agent`, `localctl` and `probectl` using the pinned Go toolchain. `signctl` performs only local key/artifact preparation. It never connects to a node, edits active configuration, restarts services or resets state. Outputs must be new paths under an operator-controlled parent.

Generate the next private key on the trusted server administration host. Keep its private directory local; distribute only public trust material through the independent local administration channel:

```sh
/usr/local/libexec/argus-c2/signctl -action generate -out /root/argus-signer-next

/usr/local/libexec/argus-c2/signctl -action stage \
  -current /etc/argus-c2/probe/task-public.pem \
  -next-public-key /root/argus-signer-next/task-public.pem \
  -retire-at "$OLD_KEY_RETIRE_AT" -valid-until "$NEW_KEY_VALID_UNTIL" \
  -out /root/argus-signer-overlap.json
```

Set the two shell variables to reviewed RFC3339 timestamps. Staging requires more than five minutes and at most 24 hours of overlap, with the new key expiring later. Choose enough time to complete deployment; the tool does not discover offline probes or extend validity automatically. For another rotation, `-current` points to the currently installed single-key trust JSON after the preceding retirement. The generated JSON is the same on the server and all affected probes. Independently compare its public fingerprints before local installation.

The historical `-task-public-key` flag and `/etc/argus-c2/probe/task-public.pem` path accept either the original PEM or explicitly migrated JSON. Retaining the path avoids changing the Phase 7 unit or granting extra filesystem access. The filename suffix does not determine its format. Preserve the previous file as maintenance evidence.

## Initial migration and signer switch

The following paths assume the Phase 7 deployment. Adapt host placement through trusted local administration: the combined local CI host is not a claim of qualified multi-host orchestration.

1. Install the reviewed overlap JSON as root:root 0644 at `/etc/argus-c2/probe/next-task-trust.json` on each probe. On the server, install the same document at `/etc/argus-c2/server/next-task-trust.json`, the current public PEM at `/etc/argus-c2/server/current-task-public.pem`, and the next public PEM at `/etc/argus-c2/server/next-task-public.pem`. Keep active files unchanged for now.
2. Drain outstanding tasks, then run `localctl -state /var/lib/argus-c2-server -action dispatch-pause` as `argus-server`. Inspect queued work with the existing task listing. If necessary, explicitly terminalize undispatched tasks using `-action dispatch-cancel-queued`. This command requires the persistent pause. Do not use node disablement merely to rotate a signer.
3. Stop the probe service on every affected node and stop the server service before replacing its private key. Take and verify cold backups using the Phase 7 recovery rules, including the complete state directories and previous configuration. A backup is not permission to restore stale replay after new work has run.
4. Run the following on each probe as `argus-probe`:

```sh
/usr/local/libexec/argus-c2/probectl -action trust-migrate \
  -state /var/lib/argus-c2-probe/replay \
  -identity /etc/argus-c2/probe/identity.json \
  -task-public-key /etc/argus-c2/probe/task-public.pem \
  -next-trust-set /etc/argus-c2/probe/next-task-trust.json
```

5. Run the following on the stopped server as `argus-server`:

```sh
/usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server \
  -action signer-trust \
  -current-task-public-key /etc/argus-c2/server/current-task-public.pem \
  -task-trust-set /etc/argus-c2/server/next-task-trust.json

/usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server \
  -action signer-switch -next-task-public-key /etc/argus-c2/server/next-task-public.pem
```

6. As root, install the reviewed trust JSON at each probe's active `/etc/argus-c2/probe/task-public.pem` and the server's `/etc/argus-c2/server/task-trust.json`, root:root 0644. Install the new matching private key at `/etc/argus-c2/server/secrets/task-private.pem`, root:root 0600, keeping its parent root:root 0700. Keep the services stopped throughout this step. Preserve previous private material according to the operator's evidence/retention decision; do not distribute it to probes.
7. Start the existing server and probe units. systemd reloads `LoadCredential` material for the new server process. Inspect `localctl -action signers`, confirm the selected key ID and installed trust generation, then use `-action dispatch-resume` as `argus-server`. Verify a fresh task-ready heartbeat and completion of an allowed read-only task.

No component automatically installs a root-owned file. The server's existing transport/issuer separation checks also apply to the newly selected private key at startup. Swapping only a file while the old process runs does not change its in-memory key; swapping only the database selection leaves that old process unable to dispatch.

## Retire the previous key

After previous assignments have completed or expired, prepare the next public generation:

```sh
/usr/local/libexec/argus-c2/signctl -action retire \
  -current /etc/argus-c2/server/task-trust.json \
  -key-id "$OLD_KEY_ID" -out /root/argus-signer-retired.json
```

Pause dispatch again and stop each probe. Locally stage this JSON at the next-trust paths. Run `probectl trust-migrate` using each probe's current active JSON and the new JSON. Run `localctl signer-trust` using `/etc/argus-c2/server/task-trust.json` as the expected current document. The selected server key must already be the retained key. Replace both public configuration copies as root while probes remain stopped, restart probes, and resume dispatch. No private-key replacement or server restart is needed for retirement alone; the server reads trust transactionally. Recheck an allowed task and the local audit.

Removing a key can shorten authority immediately on a locally updated probe, even before its scheduled expiry. An offline or unmaintained probe retains its previously installed key until its local expiry boundary. There is no remote emergency distrust protocol. A compromised signer can still request locally permitted tasks until each affected probe distrusts it; this procedure does not establish a clean host after compromise.

## Interruption and recovery boundaries

| Failure | Required behavior |
| --- | --- |
| Probe worker still running | Migration fails on the exclusive process lock |
| Unknown schema, wrong identity/current trust, corrupt replay/audit or blocked clock | Migration fails; no reset or replacement state is created |
| Audit or SQLite write fails | Trust/selection/pause transaction rolls back |
| Migration commits but command success is lost | Retry the exact transition; no duplicate trust audit event |
| Database migrated, active file still old | Keep service stopped and install the matching reviewed artifact; task startup otherwise blocks |
| Server selection changed, private file still old | Server startup or dispatch rejects the mismatch; install the reviewed matching key while stopped |
| Queued tasks remain | Signer switch refuses; drain or explicitly cancel the queue |
| Unexpired dispatched envelope would lose trust | Server trust update refuses; resolve it or wait for expiry, preserving late results |
| Old trust JSON or legacy PEM restored after migration | Probe binding rejects it; do not run replay initialization |
| All locally trusted keys expire | New task admission stops; pending results may still upload over valid TLS |
| Identity or replay state lost/restored | Follow Phase 7 quarantine/fresh-enrollment rules; rotation cannot repair replay history |

## Validation scope

Tests cover strict nested trust JSON, canonical IDs/encoding, domain and trust-ID substitution, v1 downgrade rejection, key windows, retirement and revival prevention, generation rollback, migration locking, audit failure rollback, corrupted state, interrupted-task recovery, unchanged replay/outbox/audit history, dispatch pause, explicit queue cancellation, stale server keys, immutable old envelopes, and late results through real mTLS after a signer switch. New fuzz targets cover trust documents and v2 envelope verification.

The disposable Ubuntu job also generates the next key, migrates the stopped services, replaces files through local root setup, verifies v2 dispatch, retires the old key, runs SSH inspection under the unchanged unit, and continues into cold restore/fresh enrollment with the new trust representation. These checks qualify this local increment; they do not complete the remaining Phase 8 work or qualify public listeners.
