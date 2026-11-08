# Operations

[Documentation](../README.md) · [Deployment](deployment.md) · [Configuration](configuration.md)

This page assumes the services are installed as described in the deployment guide and `argus_admin` is defined in the administrator's terminal. Replace `NODE_ID`, `TASK_ID`, and path placeholders with actual values.

## Nodes, tasks, and logs

```sh
argus_admin health
argus_admin nodes
argus_admin tasks
argus_admin result -task TASK_ID
argus_admin audit -after 0
```

`health` checks only the server database connection. Node `status=active` means the node is not disabled, not that it is online. Check `last_seen_at`; 0 means no heartbeat has arrived since enrollment. The agent cycle drives heartbeats, so collection time and retries can delay updates.

Even when a task is `SUCCEEDED`, inspect report availability and coverage. A failed task exposes its error in `result.error`. An `UNKNOWN` task may have no result object; see [State semantics](architecture.md).

```sh
sudo journalctl -u argus-c2-agent --since '30 minutes ago' --no-pager
sudo journalctl -u argus-c2-server --since '30 minutes ago' --no-pager
```

Runtime logs are structured JSON, but the API does not log every rejection in detail or audit every access. Journald may not contain the internal cause of each HTTP error. The agent message `agent cycle failed; will retry` means the loop will continue retrying.

Database audit retains approximately 100,000 events. Task and result history has manual, backup-first cleanup as described below. Host journald settings control log retention; unit `LogRateLimit*` settings limit output rate, not retained disk usage. Monitor both state-directory space and host logs.

## Administrator tokens

Generate an individual account in a private directory:

```sh
umask 077
/usr/local/libexec/argus-c2/argus new-user \
  -name observer -role ReadOnly -out /private/argus/observer.token \
  > /private/argus/observer-user.json
```

Add the complete object from `observer-user.json` to the `users` array in the server's source `/etc/argus-c2/server/admins.json`. Preserve existing accounts and verify that at least one usable Admin remains. Keep the source file root-owned and mode 0600, then restart:

```sh
sudo systemctl restart argus-c2-server
```

To revoke an account, remove its record and restart. To rotate a token, generate a replacement, replace that account's digest, restart, and deliver the new token to its administrator. Tokens do not expire automatically. Account files load at startup without hot reload. Do not edit the runtime copies under `/run/credentials`.

## Disable and reenroll a node

```sh
argus_admin disable -node NODE_ID
```

Subsequent requests using either the current or previous node certificate are rejected, including requests on existing TLS connections. Disabling does not forcibly stop read-only collection already running locally, but the disabled identity can no longer upload results.

There is no reenable or node-deletion API. To restore management, stop the agent, preserve its old state for investigation, enroll with a new private directory, token, and key, then update configuration. The new node ID does not inherit old tasks. Do not edit the database to reactivate an invalid identity or delete `probe.db` while reusing its certificate.

## Certificate maintenance

Agent certificates default to 30 days. At the beginning of a cycle, the agent attempts automatic renewal when less than seven days remain, retaining the original key. The server keeps one previous fingerprint until its original expiry to handle lost renewal responses. Node listings expose the server's current `certificate_expires_at`.

Stop the running instance to release its state lock before attempting manual renewal:

```sh
sudo systemctl stop argus-c2-agent
sudo -u argus-agent /usr/local/libexec/argus-c2/agent renew \
  -config /etc/argus-c2/agent.json
sudo systemctl start argus-c2-agent
```

With more than seven days remaining, renewal returns the existing certificate; command success does not mean a replacement was issued. Automatic renewal has a separate five-second budget. If it fails while the current certificate remains valid, a warning is logged and result uploads, heartbeat, and polling continue. Renewal retries are scheduled at most five minutes apart, sooner as expiry approaches; explicit `agent renew` still reports errors directly. Expired or not-yet-valid certificates cannot use this fallback. Renewal cannot repair a leaked key, an expired certificate, or lost state; disable and reenroll those identities.

The CA defaults to five years and the server certificate to one year. There is no automatic server-certificate renewal command. Before expiry, use standard PKI tools to issue a certificate under the same trusted CA with the required SANs and serverAuth purpose. Stop the server, install its matching certificate and key, check credentials, and restart. Preserve recovery material. Replacing the CA requires separately arranging node trust and identities; there is no automatic trust-root switch.

Monitor the public certificates from a local scheduled check:

```sh
sudo -u argus-server /usr/local/libexec/argus-c2/server certificates \
  -config /etc/argus-c2/server.json -warn-before 720h
```

The command prints server/issuer validity and fingerprints and exits nonzero if either is within 30 days of expiry, expired, or not yet valid. It needs no private-key access and installs no scheduler; connect it to existing host monitoring. It checks files on disk, so separately verify the served certificate after rotation. A successful `argus health` alone is not a certificate-lifetime check.

For repeatable same-root server leaf rotation: back up the old leaf/key separately, issue a new distinct server key and leaf with the same required SANs/serverAuth, validate it with a private configuration, stop the service, install the matching pair with existing ownership/modes, and restart. Check the served fingerprint, management access, an already enrolled agent heartbeat, and pending-result delivery. Roll back to the preserved unexpired pair if validation fails; never disable TLS verification. [The rotation integration test](../test/integration/server_rotation_test.go) exercises reconnect and upload with unchanged node identity and rejection of an expired replacement. A stolen old leaf remains trusted until expiry or explicit trust replacement; see [incident response](security.md#online-root-exposure-and-incident-response).

## Database compatibility and upgrades

For standard Linux/systemd installations, the release installer supports `--update server` and `--update agent`. It verifies the bundle, snapshots stopped state/configuration and old programs, checks a copy with the candidate, and restores previous programs on failure without rewinding the live database. See [update commands and recovery](server-installation.zh-CN.md#更新-server-或-agent). The installer supports the explicit 102/103 → 104 migration on a stopped-state copy. If schema replacement has begun and service checks fail, it preserves the new programs and current state and stops the service rather than rewinding possibly accepted work. Custom deployments and other migrations use the explicit procedure below.

The server requires Schema **103**; the agent remains on Schema **101**, independently versioned. Server databases have SQLite application ID `0x41524753` (`ARGS`); agent databases use `0x41524741` (`ARGA`). Server Schema 101 is incompatible with 102 because it lacks trusted receipt and durable execution-authorization timestamps and the task-query indexes. Wrong-component and other unsupported versions are rejected; startup never resets or converts them. Do not change `PRAGMA user_version` to bypass the check.

Before replacing binaries:

1. Record the old/new commit, protocol version, each component's schema version, and current configuration. Protocol 1 compatibility does not imply database compatibility.
2. Create a verified server snapshot with the old compatible binary. Separately preserve configuration, CA/TLS material, account configuration, and revocations since the snapshot. Stop each agent before preserving its entire identity/state directory; retain the old binaries.
3. Test the new binaries against **copies** in an isolated environment, with agent access blocked. Check schema acceptance, administration, result reads, and restart behavior. Never run a copied agent identity alongside the original.
4. For updates compatible with each component's current schema, stop services, install binaries, run appropriate configuration checks, restart, and inspect heartbeat/report behavior before broader rollout.
5. For server schema 102 or 103, stop the old server and run `server console-migrate -config FILE -backup NEW_PRIVATE_FILE` with the new binary. It verifies/syncs an original-version snapshot before transactional migration to 104. The original data remains intact; failures roll back and startup refuses the old schema. Preserve unsupported older development state separately. Do not silently discard pending results or reuse a certificate with a new agent database.

The only shipped migration is 102 → 103; there is no general historical migration chain or downgrade framework. See [Console migration and recovery](console.md). Rollback requires a binary that supports the database being restored and the identity reconciliation below; restoring both agent and server snapshots can break deduplication continuity.

## Online backup

Database backup uses SQLite `VACUUM INTO`, including WAL data committed at snapshot time. It does not copy a database file while it is being written. In a systemd deployment, run it as the service user to avoid creating root-owned SQLite sidecars:

```sh
sudo install -d -o argus-server -g argus-server -m 0700 \
  /var/lib/argus-c2-server/backups
ARGUS_BACKUP="/var/lib/argus-c2-server/backups/fleet-$(date -u +%Y%m%dT%H%M%SZ).db"
sudo -u argus-server /usr/local/libexec/argus-c2/server backup \
  -config /etc/argus-c2/server.json -out "$ARGUS_BACKUP"
```

`backup` loads the configuration structure and database without reading `/run/credentials` paths, so the actual service configuration can be used. The output must not exist and its parent should be private. The file is created exclusively with mode 0600, checked with SQLite integrity/schema validation, then synced. Failure can leave an incomplete output; only a successful backup is a verified snapshot. A busy database can exceed the two-second busy timeout. Keep the original state and retry during lower activity; do not delete WAL files to resolve locking.

A database snapshot excludes the CA private key, server certificate and key, `admins.json`, raw administrator tokens, and agent configuration and policy. Back up those materials separately with restricted access. Copy snapshots to independent storage: the directory above is a snapshot destination on the same host and cannot protect against host or disk loss.

## Server history retention

No background job deletes task history. Run `server prune` as the server service user; default behavior is preview, retaining 30 days with at most 200 candidate tasks. `-retain-days` and `-unknown-days` each accept 1–36,500 and `-limit` accepts 1–1,000. Matching terminal task/result records (`SUCCEEDED`, `FAILED`, or persisted `UNKNOWN`) qualify only when server `received_at` is strictly older than the result cutoff. UNKNOWN without a result uses a separate `-unknown-days` interval, default 90 days, measured after the later of its dispatch and result deadlines. Active PENDING/ACCEPTED/RUNNING records remain protected; preview does not run expiry maintenance.

Each cutoff is server time minus its configured number of 24-hour days. **Result retention starts at first server receipt**, including delayed uploads and server-generated terminal reports. Old or future Agent `completed_at` values do not affect eligibility; duplicate uploads never refresh `received_at`. A late result arriving for an UNKNOWN candidate before deletion invalidates that frozen candidate and aborts the entire batch. Synchronize server time; substantial server clock jumps can affect age calculations.

```sh
sudo -u argus-server /usr/local/libexec/argus-c2/server prune \
  -config /etc/argus-c2/server.json -retain-days 30 -unknown-days 90 -limit 200
```

Review the returned task IDs, node IDs, statuses, `has_result`, server `retained_at`, and both Unix cutoffs. To apply, first create the private backup directory shown in Online backup, then choose a new snapshot path:

```sh
ARGUS_PRUNE_BACKUP="/var/lib/argus-c2-server/backups/pre-prune-$(date -u +%Y%m%dT%H%M%SZ).db"
sudo -u argus-server /usr/local/libexec/argus-c2/server prune \
  -config /etc/argus-c2/server.json -retain-days 30 -unknown-days 90 -limit 200 \
  -apply -backup "$ARGUS_PRUNE_BACKUP"
```

Apply recomputes and freezes a bounded candidate list, creates a verified nonoverwriting snapshot, then revalidates and deletes the batch in one transaction. Results arriving after the list was frozen cannot join that batch. The returned JSON is the applied list, which can differ from a previous preview. A stale candidate, backup failure, audit failure, or failed deletion aborts cleanup; a successful backup can remain after a later transaction failure. Inspect the error and current state before retrying with a new backup path. Run one cleanup operator at a time.

Each removed task (with or without a result) produces a `task.prune` audit event with its IDs and original terminal state. Prior audit is not cascaded away, but appending events still enforces the existing 100,000-event capacity. Export audit pages to separately protected storage when longer evidence retention is required. Backups contain deleted reports and require their own retention and access policy; pruning is not secure erasure and may not shrink the SQLite file. Freed pages can be reused. No automatic VACUUM or backup deletion is performed.

Deleted tasks disappear from management queries. Late repeated result uploads receive explicit `task_not_found` and remain on the agent as held reports for operator attention. This also applies when a result arrives after a resultless UNKNOWN has been pruned. No false acknowledgment, task recreation, or recollection occurs. Agent deduplication is unchanged; expired assignments remain ineligible for execution even after local deduplication cleanup. New tasks always receive newly generated IDs.

For recovery, inspect the pre-prune snapshot in isolation first. Restoring it to production rolls back **all** server state, including later tasks, enrollments, renewals, and disabling; follow the full restore procedure below. Never overwrite a live database or manually insert a task with the old ID to make an upload pass. Local result discard remains a separate explicit operator action.

## Restore the server database

Restoration returns state to the snapshot time. **Before restoring, restrict agent access while retaining a controlled management connection.** Keep that restriction in place through the entire identity reconciliation. Stop the service and verify that the backup is a server database. Preserve the current database and sidecars for investigation or rollback. The example below assumes `/private/restore/fleet.db` is a verified backup:

```sh
sudo systemctl stop argus-c2-server
ARGUS_RESTORE_ARCHIVE="/var/lib/argus-c2-server/before-restore-$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 0700 "$ARGUS_RESTORE_ARCHIVE"
for suffix in '' '-wal' '-shm' '-journal'; do
  if sudo test -e "/var/lib/argus-c2-server/argus.db$suffix"; then
    sudo mv "/var/lib/argus-c2-server/argus.db$suffix" "$ARGUS_RESTORE_ARCHIVE/"
  fi
done
sudo install -o argus-server -g argus-server -m 0600 \
  /private/restore/fleet.db /var/lib/argus-c2-server/argus.db
```

Verify that the CA, certificates, keys, and administrator configuration match the restore target. Start the server with agent access still restricted:

```sh
sudo systemctl start argus-c2-server
```

Verify administrator and ReadOnly access. Reapply node disabling that occurred after the snapshot using reliable operational records independent of that snapshot, then verify both current and previous node certificates are rejected. If those records are incomplete or an identity cannot be confirmed, keep agent access restricted and reconcile manually. Only reopen access after checking nodes, tasks, results, and permissions.

Nodes, certificates, or results created after backup may be absent. An authorized agent's explicit `task_not_found` or `result_conflict` becomes a held local result; inspect and export it before deciding to retry or discard. Identity failures require separate reconciliation or reenrollment. A generic 404 is not proof that the task no longer exists. There is no automatic merge of restored state.

An ordinary server restart preserves current tasks and results. Restoring old snapshots differs: rolling both server and agent back can permit work that already happened, so it cannot guarantee strict deduplication. Manage the agent's key, certificate, and `probe.db` together as one identity set; do not restore only one file.

## Local result maintenance and storage

Stop the agent to release its exclusive state lock. These commands run offline, including with an expired certificate, and display only local delivery state. Use actual task IDs:

```sh
sudo systemctl stop argus-c2-agent
sudo -u argus-agent /usr/local/libexec/argus-c2/agent results -config /etc/argus-c2/agent.json
sudo -u argus-agent /usr/local/libexec/argus-c2/agent storage -config /etc/argus-c2/agent.json
sudo -u argus-agent /usr/local/libexec/argus-c2/agent result-export \
  -config /etc/argus-c2/agent.json -task TASK_ID -out /var/lib/argus-c2-agent/report.json
```

`results -after ID` continues a 200-record page. `pending` awaits delivery; `held` requires operator attention; `acknowledged` records server confirmation; `discarded` means the operator removed local report contents. Held contents still count toward the 1,000-record/32 MiB capacity bound.

After resolving the cause, `agent result-retry -config /etc/argus-c2/agent.json -task TASK_ID` makes a held result pending again. If it must be abandoned, `agent result-discard -config /etc/argus-c2/agent.json -task TASK_ID` displays consequences and asks you to type that task ID. For explicit noninteractive confirmation, add `-confirm-task TASK_ID`.

Discard preserves the assignment and deduplication record; it does not cancel the server task or acknowledge delivery. A server without the report may remain UNKNOWN. Discarded content cannot be uploaded or reconstructed by recollecting. The agent never discards results because retries are exhausted. Restart the agent after maintenance.

`server storage -config /etc/argus-c2/server.json`, run as the server service user, reports database/WAL file sizes and available filesystem space without loading service credentials. The agent storage command additionally reports pending/held count, reserved-plus-actual bytes, held count, and discarded count. On Linux, space warnings mean less than 64 MiB or 10% of filesystem capacity is available. These warnings are observations, not reservations or guarantees of write success. Task/result history is cleaned manually with `server prune`; no scheduler is installed.

## Troubleshooting

| Symptom | Possible cause and response |
| --- | --- |
| `private key must not be accessible...` | Credential permissions are too broad; check ownership and mode 0600 or systemd credential delivery |
| `state directory must be private...` | Directory permissions, symlinks, or incorrect paths; use a regular mode-0700 directory owned by the service user |
| `incompatible database` | Wrong component or unsupported schema; verify the configured path and preserve the file before initializing separate state |
| `another probe worker holds...` | An agent already holds the state lock; stop it before manual execution or renewal instead of deleting the lock file |
| Missing `probe.db` during agent startup | Enrolled identity lost deduplication state; preserve remaining material, disable, and reenroll |
| Repeated agent HTTP 401 | Disabled node, expired/mismatched certificate, or server restored to older identity state |
| Management CLI HTTP 401/403 | Invalid/unloaded account token or ReadOnly attempting a mutation; restart the server after account changes |
| HTTP 409 | Full queue, disabled node, result conflict, or invalid transition; query current state first |
| Held `task_not_found` / `result_conflict` | Server may have restored an old snapshot or pruned that history; inspect/export the report and reconcile using local maintenance |
| HTTP 426 / incompatible protocol | Use a supported matching deployment; pending data is retained and must not be reset |
| `local_policy_denied` | Task type and resource mapping are not both permitted; update local policy and restart the agent |
| `execution_authorization_rejected` / `execution_authorization_uncertain` | Grant denied or response uncertain; no collection starts, a terminal local report is retained for reconciliation without redelivery |
| `task_from_future` / `task_expired` | Clock or TTL issue; synchronize time, then create a new task |
| `collector_timeout` | CPU sampling, system bus, or local resource delay; check sampling and execution budgets |
| `result_too_large` | Valid report exceeds the local limit; adjust scope or budget; raw truncated output is not uploaded |
| `agent_interrupted` / `running_persistence_interrupted` / `result_persistence_interrupted` | Outcome is uncertain; investigate restart/storage issues, then submit a new task ID if another observation is needed |
| `SUCCEEDED` with unavailable data | Collection completed but resources were unreadable/unavailable; check OS permissions and report codes in [Collectors](collectors.md) |
| `database is locked` / write failure | Concurrent maintenance, disk, permission, or load issue; resolve the resource problem, preserve state, and retry |

Network outages are retried automatically with a maximum backoff of about 61 seconds, excluding request time within the cycle. Startup failures follow the systemd unit's restart policy. If its start-rate limit is reached, fix the cause before running `systemctl reset-failed` and starting the service.
