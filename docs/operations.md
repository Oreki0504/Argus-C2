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

Database audit retains approximately 100,000 events. Task and result history has no automatic cleanup. Host journald settings control log retention; unit `LogRateLimit*` settings limit output rate, not retained disk usage. Monitor both state-directory space and host logs.

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

With more than seven days remaining, renewal returns the existing certificate; command success does not mean a replacement was issued. Renewal happens before pending-result uploads and heartbeats, so a failure can prevent the rest of that cycle. Renewal cannot repair a leaked key, an expired certificate, or lost state; disable and reenroll those identities.

The CA defaults to five years and the server certificate to one year. There is no automatic server-certificate renewal command. Before expiry, use standard PKI tools to issue a certificate under the same trusted CA with the required SANs and serverAuth purpose. Stop the server, install its matching certificate and key, check credentials, and restart. Preserve recovery material. Replacing the CA requires separately arranging node trust and identities; there is no automatic trust-root switch.

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

`server storage -config /etc/argus-c2/server.json`, run as the server service user, reports database/WAL file sizes and available filesystem space without loading service credentials. The agent storage command additionally reports pending/held count, reserved-plus-actual bytes, held count, and discarded count. On Linux, space warnings mean less than 64 MiB or 10% of filesystem capacity is available. These warnings are observations, not reservations or guarantees of write success. Task/result history has no automatic server retention policy.

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
| Held `task_not_found` / `result_conflict` | Server may have restored an old snapshot; inspect/export the retained report and reconcile it using local maintenance |
| HTTP 426 / incompatible protocol | Use a supported matching deployment; pending data is retained and must not be reset |
| `local_policy_denied` | Task type and resource mapping are not both permitted; update local policy and restart the agent |
| `task_from_future` / `task_expired` | Clock or TTL issue; synchronize time, then create a new task |
| `collector_timeout` | CPU sampling, system bus, or local resource delay; check sampling and execution budgets |
| `result_too_large` | Valid report exceeds the local limit; adjust scope or budget; raw truncated output is not uploaded |
| `agent_interrupted` / `running_persistence_interrupted` / `result_persistence_interrupted` | Outcome is uncertain; investigate restart/storage issues, then submit a new task ID if another observation is needed |
| `SUCCEEDED` with unavailable data | Collection completed but resources were unreadable/unavailable; check OS permissions and report codes in [Collectors](collectors.md) |
| `database is locked` / write failure | Concurrent maintenance, disk, permission, or load issue; resolve the resource problem, preserve state, and retry |

Network outages are retried automatically with a maximum backoff of about 61 seconds, excluding request time within the cycle. Startup failures follow the systemd unit's restart policy. If its start-rate limit is reached, fix the cause before running `systemctl reset-failed` and starting the service.
