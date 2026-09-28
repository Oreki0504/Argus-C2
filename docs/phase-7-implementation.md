# Argus-C2 Phase 7: Linux Service Hardening and Recovery

Phase 7 supplies visible, manually installed systemd services, separate non-root accounts, root-controlled configuration, credential delivery, resource limits, and native deployment/recovery exercises. The existing four read-only task types and probe-local authority boundary are unchanged. A new local `restore-quarantine` operation contains the authority resurrected by a restored server database.

The validated baseline is the GitHub-hosted Ubuntu 24.04 x86-64 VM, systemd 255 and cgroup v2, with native Linux file-resolution and D-Bus tests. Other distributions, containers, architectures, and administrator overrides need their own validation. The application still accepts only literal loopback listeners. These assets qualify local service operation; they do not make this a production-ready, multi-VPS release. Public listeners, production certificate renewal, automatic retention, and remote rollout remain unimplemented.

## Service layout and limits

| Location | Owner and mode | Purpose |
| --- | --- | --- |
| `/usr/local/libexec/argus-c2/` | root:root 0755; binaries 0755 | Reviewed executables, never service-writable |
| `/etc/argus-c2/server/`, `/etc/argus-c2/probe/` | root:root 0755 | Public certificates, trust anchors, probe identity and policy, files 0644 |
| Each `secrets/` directory | root:root 0700; keys 0600 | Original private keys read by the service manager |
| `/etc/systemd/system/argus-c2-*.service` | root:root 0644 | Locally administered units and drop-ins |
| `/var/lib/argus-c2-server/` | argus-server:argus-server 0700 | Server database and its SQLite sidecars |
| `/var/lib/argus-c2-probe/` | argus-probe:argus-probe 0700 | Replay database in `replay/`, pending results, local audit |

Both accounts have `/usr/sbin/nologin`, no administrative groups, no sudo policy, and no Docker or equivalent privileged socket access. All ancestors of program/configuration paths must also be root-controlled, without writable ACLs or unexpected symlinks. Public identity and certificate files contain no private key. Do not put passwords or tokens in policy, unit files, environment variables, or command arguments.

The units use `LoadCredential=` and `%d` to provide private, read-only runtime key files. Original keys stay in root-only directories; the application loads its own credentials after systemd starts it as the service user. This does not hide keys from the process that must use them, root, or a compromised service. `ProtectSystem=strict` restricts filesystem writes, while `ProtectHome=true` hides home directories. Private temporary directories remain writable. These controls complement application allowlists; they are not a general read allowlist. See the [systemd 255 execution documentation](https://github.com/systemd/systemd/blob/v255/man/systemd.exec.xml).

Both units clear effective/bounding/ambient capabilities, enable `NoNewPrivileges`, restrict namespaces and address families, apply `@system-service` syscall filtering, disable writable-executable memory, protect kernel/control-group settings, and set a private umask. `/proc` remains sufficient for fixed system metrics; unrelated processes are hidden. Home-directory SSH inspection remains unavailable. Do not weaken `ProtectHome` or add privileged groups to eliminate a coverage gap.

Only `argus-c2-probe.service` sets `RestrictSUIDSGID=false`: [systemd 255 implements that restriction by blocking `openat2`](https://github.com/systemd/systemd/blob/v255/src/shared/seccomp-util.c), which the probe requires for constrained SSH-file reads. The server retains `RestrictSUIDSGID=true`. Every other hardening setting remains enabled, including `NoNewPrivileges`, empty capabilities and root-controlled programs/policy. Both units additionally use `NoExecPaths` for their writable state, `/tmp`, and `/var/tmp`; CI checks that direct execution from these paths is denied. This is a documented exception to the proposed Phase 1 baseline: the probe loses this systemd filter against creating SUID/SGID mode bits, while privilege gain through execution remains blocked. SSH auditing keeps constrained `openat2` and has no ordinary `open`/`openat` fallback. `NoExecPaths` does not prevent an interpreter from reading a script and is not a substitute for the fixed task protocol.

On Linux, systemd can express credential access with a named-user ACL whose read mask appears in the group mode bits. Argus accepts only the exact root-owned, read-only ACL granting this service UID read access, with no owning-group or other access. It checks the opened file descriptor and bounded ACL bytes; an environment variable or credential-looking path cannot bypass the normal private-file rule. Ordinary group-readable keys remain rejected. This accommodates [systemd's credential implementation](https://github.com/systemd/systemd/blob/v255/src/core/exec-credential.c).

| Setting | Server | Probe |
| --- | --- | --- |
| CPU quota, as a fraction of one CPU | 100% | 50% |
| MemoryHigh / MemoryMax | 384 / 512 MiB | 128 / 192 MiB |
| Swap allowance | 0 | 0 |
| Task/thread limit | 128 | 128 |
| Open descriptors / core dump size | 1,024 / 0 | 1,024 / 0 |
| Failure restart delay / start budget | 10 seconds / 3 starts per 300 seconds | Same |
| Graceful-stop deadline | 15 seconds | 15 seconds |

MemoryHigh applies pressure; MemoryMax is the hard limit. CPU quotas may delay requests, and an OOM stop can leave an in-flight task indeterminate. Limits bound resource use without guaranteeing availability. The server allowance includes the two concurrent 64 MiB password KDFs. Verify actual cgroup values and workload behavior before locally changing limits; see [systemd resource controls](https://github.com/systemd/systemd/blob/v255/man/systemd.resource-control.xml). Kernel-blocked filesystem calls are not made interruptible by a Go deadline or systemd stop timeout. Avoid network/FUSE mounts in telemetry mappings.

## Build and manually install on a fresh test VM

This example installs both roles on one disposable Linux VM because the current endpoints are loopback-only. Use a trusted checkout and Go 1.27.1. Build as an ordinary development user, review the files, and use sudo only for the explicit installation steps. Do not run the CI fixture on a real host.

```sh
mkdir -p .cache/deployment-bin
for command in server agent localctl probectl enroll cli devpki devsign; do
  GOTOOLCHAIN=go1.27.1 CGO_ENABLED=0 go build -trimpath \
    -o ".cache/deployment-bin/$command" "./cmd/$command"
done
go test ./... -count=1
```

Before installing, confirm that the two account names, configuration directories, state directories, and units do not already belong to another installation. Inspect ancestors with `namei -l`; resolve unexpected ownership, symlinks, or ACLs locally. The following is a fresh-install recipe, not an upgrade or overwrite script. Install only the role assets needed on a host when developing a different topology.

```sh
sudo systemd-sysusers deploy/linux/argus-c2-server.sysusers.conf
sudo systemd-sysusers deploy/linux/argus-c2-probe.sysusers.conf
id argus-server
id argus-probe
sudo install -d -o root -g root -m 0755 /usr/local/libexec/argus-c2
for command in server agent localctl probectl enroll cli; do
  sudo install -o root -g root -m 0755 ".cache/deployment-bin/$command" "/usr/local/libexec/argus-c2/$command"
done
sudo install -d -o root -g root -m 0755 /etc/argus-c2 /etc/argus-c2/server /etc/argus-c2/probe
sudo install -d -o root -g root -m 0700 /etc/argus-c2/server/secrets /etc/argus-c2/probe/secrets
sudo install -d -o argus-server -g argus-server -m 0700 /var/lib/argus-c2-server
sudo install -d -o argus-probe -g argus-probe -m 0700 /var/lib/argus-c2-probe
sudo install -o root -g root -m 0644 deploy/linux/argus-c2-server.service deploy/linux/argus-c2-probe.service /etc/systemd/system/
```

For this isolated test only, generate 24-hour development credentials. The development CA cannot support a production renewal plan. Keep the generated directory private and outside version control. An actual PKI deployment needs a separate lifecycle design before network exposure.

```sh
.cache/deployment-bin/devpki -enrollment -out .local/phase7-pki
.cache/deployment-bin/devsign -out .local/phase7-signing
sudo install -o root -g root -m 0644 .local/phase7-pki/ca.pem .local/phase7-pki/server-cert.pem .local/phase7-pki/issuer-cert.pem /etc/argus-c2/server/
sudo install -o root -g root -m 0600 .local/phase7-pki/server-key.pem .local/phase7-pki/issuer-key.pem /etc/argus-c2/server/secrets/
sudo install -o root -g root -m 0600 .local/phase7-signing/task-private.pem /etc/argus-c2/server/secrets/
sudo install -o root -g root -m 0644 .local/phase7-pki/ca.pem .local/phase7-signing/task-public.pem /etc/argus-c2/probe/
sudo install -o root -g root -m 0644 examples/task-policy-v2.json /etc/argus-c2/probe/policy.json
sudo -u argus-server /usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server -action user-add -username operator -role Admin
```

The last command prompts privately for a new password and initializes server state. Account administration always executes as the dedicated non-root server user. Do not grant that filesystem authority to a network ReadOnly administrator. For normal CLI use, choose a private session directory belonging to the human operator, outside server state; see [Phase 6](phase-6-implementation.md).

Enable enrollment temporarily by installing the supplied drop-in. It exposes only `127.0.0.1:8444` and loads a separate issuer credential. Check the effective configuration before starting:

```sh
sudo install -d -o root -g root -m 0755 /etc/systemd/system/argus-c2-server.service.d
sudo install -o root -g root -m 0644 deploy/linux/enrollment.conf.example /etc/systemd/system/argus-c2-server.service.d/enrollment.conf
sudo systemd-analyze verify /etc/systemd/system/argus-c2-server.service /etc/systemd/system/argus-c2-probe.service
sudo systemctl daemon-reload
sudo systemctl start argus-c2-server
sudo systemctl status argus-c2-server --no-pager
```

Enroll as the probe account, passing the one-use token directly through stdin. Run these commands in a shell with `set -o pipefail`; a failed pipeline requires inspection, not automatic retry. The output directory must be new. Enrollment failure after server commit may leave an orphaned node, which must be disabled before a fresh attempt.

```sh
set -o pipefail
sudo -u argus-server /usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server -action token -ttl 2m |
  sudo -u argus-probe /usr/local/libexec/argus-c2/enroll -server https://127.0.0.1:8444 -ca /etc/argus-c2/probe/ca.pem -out /var/lib/argus-c2-probe/enrollment
sudo install -o root -g root -m 0644 /var/lib/argus-c2-probe/enrollment/identity.json /var/lib/argus-c2-probe/enrollment/probe-cert.pem /etc/argus-c2/probe/
sudo install -o root -g root -m 0600 /var/lib/argus-c2-probe/enrollment/probe-key.pem /etc/argus-c2/probe/secrets/
sudo -u argus-probe /usr/local/libexec/argus-c2/probectl -action init -state /var/lib/argus-c2-probe/replay -identity /etc/argus-c2/probe/identity.json -task-public-key /etc/argus-c2/probe/task-public.pem
```

After confirming the installed key and identity, remove the duplicate enrollment key from the service-writable staging directory through local administration; keep any required enrollment evidence in private operator custody. Preserve the root-controlled installed key. Stop if replay state already exists: `init` is never a reset operation.

```sh
sudo systemctl start argus-c2-probe
sudo systemctl status argus-c2-probe --no-pager
sudo -u argus-server /usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server -action nodes
```

Inspect the ready heartbeat and complete a `system.info` task through the authenticated CLI before enabling boot startup. The shipped v2 policy enables only system information/metrics; SSH and service inspection require explicit root-owned local mappings. CI enables a synthetic SSH configuration and a fixed journald query to exercise those paths under the same restrictions.

After enrollment, remove exactly `/etc/systemd/system/argus-c2-server.service.d/enrollment.conf`, run `systemctl daemon-reload`, and restart the server. Confirm port 8444 is closed. Move the unused issuer private key to protected operator custody off the application host when no longer needed. Confirm normal CLI login and probe collection still work. Only then, if persistent startup is desired, run `sudo systemctl enable argus-c2-server argus-c2-probe`.

## Observe, pause, stop, upgrade, and remove

`systemctl cat` shows all local overrides; `systemd-analyze security` provides diagnostic hints rather than a proof of containment. Inspect effective unit settings and actual cgroup values:

```sh
sudo systemctl cat argus-c2-server argus-c2-probe
sudo systemctl show argus-c2-probe -p User -p Group -p NoNewPrivileges -p CapabilityBoundingSet -p ProtectSystem -p ProtectHome -p ControlGroup -p MemoryMax -p CPUQuotaPerSecUSec -p TasksMax
sudo journalctl -u argus-c2-server -u argus-c2-probe --since '10 minutes ago' --no-pager
sudo ss -ltnp
```

Status should show non-root identities and only expected loopback listeners. A process being `active` is not evidence that task state is ready. Inspect the node's `task_state`, freshness, results, and audit through the CLI. The systemd log rate limit is separate from durable security auditing in SQLite. Monitor clock synchronization, free disk space, certificate expiry, restart limits, OOM events, and audit/replay capacity.

Set `paused: true` in the root-owned probe policy to stop new task execution while continuing health reporting. The probe reloads policy each cycle and again before admission. Use an atomic local file replacement with the same owner/mode. A full stop is `sudo systemctl stop argus-c2-probe`; it is visible and does not resist removal. Stopping cannot undo already completed tasks or interrupt every blocked kernel call immediately.

For an upgrade, stop the affected services, take a cold evidence/backup copy, replace only reviewed binaries and unit files as root, verify configuration, reload systemd, and restart. Preserve identities, policy, trust anchors and replay state. Test the database migration before rollout. Do not downgrade a migrated database or restore a previous replay snapshot to make an older binary start. A rollback involving database restoration follows quarantine and fresh enrollment below.

To remove the installation, first stop and disable both units, then remove their explicitly named unit/drop-in files and run `systemctl daemon-reload`. Retain state, keys, and audit evidence according to the operator's retention decision. Remove application files and service accounts only after reviewing their exact paths and ownership; never recursively delete a computed installation path. There is no self-update service, remote installer, hidden watchdog, or service-side uninstall resistance.

## Cold backup and restore quarantine

This phase provides an operator-run cold-backup procedure, not an online backup scheduler. Stop all server writers, including the service, enrollment listener, CLI maintenance processes, and any concurrent `localctl` invocation. Copy the entire private state directory, including any WAL/journal sidecars, together with matching keys, certificates, trusted configuration and the reviewed binary version. Restrict and encrypt the backup under separate operator control; retain external audit head checkpoints. Verify a copy on an isolated VM before relying on it. Copying only a live SQLite database can omit committed WAL data; consult [SQLite's corruption guidance](https://www.sqlite.org/howtocorrupt.html).

Never overwrite the only available evidence during restore. Keep the replaced directories in a private quarantine location. Restore into a separately reviewed directory while all listeners remain stopped; ensure every database/sidecar is a private regular file and the directory belongs to `argus-server` with mode 0700. Then run:

```sh
sudo -u argus-server /usr/local/libexec/argus-c2/localctl -state /var/lib/argus-c2-server -action restore-quarantine
```

The command commits the following changes atomically with audit records:

- Disable every enabled node in the restored database.
- Set queued tasks to rejected and dispatched tasks to indeterminate; preserve completed results and existing evidence.
- Revoke all administrator sessions and advance credential generations, including password verifications already in progress.
- Mark every stored enrollment token consumed so a backup cannot resurrect a token.

If auditing or storage fails, the whole operation rolls back; keep services stopped. Existing task/node/session audit reservations are consumed where applicable. A fully exhausted audit with no remaining reservation can still prevent recovery; never edit audit rows to bypass it. Preserve evidence and rebuild from fresh trusted state when controlled recovery cannot proceed.

Quarantine does not infer account changes made after the backup. Before starting management, review all restored accounts/roles against independently retained records, disable access that should no longer exist, and reset affected passwords through local administration. Do not reuse keys believed compromised. Whole-server compromise requires clean rebuild and independent trust-key replacement on every affected node; restoring a database cannot establish trust in the old software, keys, or history.

Start only the server after review. Keep old probes stopped until their old node identities are confirmed disabled. Re-enroll each probe explicitly into a new identity/epoch and new replay directory; do not associate fresh empty replay state with an existing active identity. Copy new public identity/certificate files into root-controlled locations, install the new private key, initialize replay state once, and restart the probe. Close enrollment again after the recovery window. This deliberately favors safe recovery over seamless continuation.

The native CI exercise restores a cold server snapshot, quarantines it, rejects its old session, verifies old node disablement, preserves missing probe-state evidence, and then proves fresh enrollment can execute an approved task. These are recovery mechanics, not automatic detection of coherent disk/clock rollback.

## Missing probe state, capacity, and compromise exercises

The packaged units require existing database files before starting. They never initialize replay state automatically. If the directory is lost, preserve evidence, stop the probe, disable the old node, and follow the fresh-enrollment procedure. A corrupt or mismatched database also needs explicit local review. The bare development probe can remain telemetry-only when replay state is unavailable; that does not authorize bypassing the packaged startup guard.

For an ordinary process crash with intact replay state, restart normally. Accepted but unfinished tasks become indeterminate and are not executed again. A cgroup OOM or forced stop follows that same persistent admission rule. Audit-write failures block new operations. Server task storage is bounded at 10,000 records, probe replay storage at 8,192, and each audit at 100,000 events. Automatic rotation/compaction is not implemented. Capacity planning and externally retained evidence are prerequisites for any longer-running pilot; deleting history to resume an active identity breaks the replay model.

The validation matrix combines existing adversarial protocol tests with the new deployment exercises:

| Scenario | Evidence |
| --- | --- |
| Compromised signer requests unknown commands, arbitrary parameters, another node/epoch, or expanded resources | Signed-server and inspection tests reject before collector invocation |
| Local pause or policy change after task queueing | Real mTLS task tests and policy reload tests retain local authority |
| Duplicate delivery, interrupted execution, clock rollback, audit write failure | Persistent replay/recovery tests, including process restart |
| Unit privilege or filesystem escape | Native service checks verify empty capabilities, no new privileges, denied writes, hidden home/host tmp, and cross-account denial |
| Hardening breaks useful collection | Real services complete system information, metrics, fixed SSH-file inspection, and D-Bus status tasks |
| Declared limits are not effective | Native checks read CPU, memory, swap, and task limits from cgroup v2 |
| Database restore resurrects authority | Atomic quarantine tests and cold restore/fresh-enrollment exercise |

The `deployment` CI job uses a fresh Ubuntu VM, installs disposable accounts and services, and runs `test/deployment/systemd_smoke.py --disposable-ci`. It fails if expected accounts/paths already exist. The CI-only Python checker is injected as an extra `ExecStartPre`; it is not shipped as a runtime dependency or an application command. Both real executables still run under the installed unit restrictions. No test credential or database is committed or uploaded as an artifact.

Linux/Windows build, vet, unit/TLS integration tests, Linux race detection, vulnerability checks, native systemd inspection, and bounded fuzz smoke tests remain enabled. Longer fuzz campaigns, independent security review, production PKI renewal, off-host audit export/retention, multi-host transport/deployment, and operational load qualification remain work beyond this baseline.
