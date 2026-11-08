# Development and validation

[Documentation](../README.md) · [Architecture](architecture.md) · [Deployment](deployment.md)

Argus-C2 is under development and has not reached an MVP release. This page distinguishes test coverage, recorded runs, and remaining acceptance. Baseline `8fe8997` passed [GitHub Actions run 41864153776](https://github.com/Oreki0504/Argus-C2/actions/runs/41864153776), including actual filesystem exhaustion and native systemd deployment. Subsequent changes need their own run; baseline success is not evidence for an untested working tree. GitHub Actions is the current acceptance environment. Five independent VPS instances and a 72-hour observation window remain a separate deferred stage.

## Build environment

The Go baseline is **1.27.3**. Dependencies are defined in [go.mod](../go.mod) and [go.sum](../go.sum). The server uses pure-Go SQLite, so deployment binaries can be built with `CGO_ENABLED=0`. The race detector requires a supported CGO toolchain; do not disable CGO globally for race checks.

Agent enrollment and execution require Linux and a non-root user. Windows CI builds and tests the supported portions, while Linux collection integration skips on other platforms. A successful Windows cross-build does not establish deployable Windows agent support.

## Basic checks

Run from the repository root:

```sh
go build ./...
go vet ./...
go test ./... -count=1
go test -race ./... -count=1
GOOS=windows GOARCH=amd64 go build ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

Check native read-only systemd queries separately:

```sh
ARGUS_REQUIRE_SYSTEMD=1 go test ./internal/collectors/services \
  -run '^TestLiveSystemdReadOnly$' -count=1 -v
```

Without `ARGUS_REQUIRE_SYSTEMD=1`, the live query can skip when no system bus is available. An ordinary passing test run alone does not establish live systemd access.

## Behavior and test coverage

| Behavior | Test location and coverage |
| --- | --- |
| Five separate node identities, all six task types from submission to result, role restrictions | [fleet_test.go](../test/integration/fleet_test.go): `TestFiveNodeDiagnosticsAndAuthorization` |
| Server outage after collection, SQLite reopen, delayed upload, repeated/conflicting results, snapshot restore | Same file: `TestServerRestartOutageAndLateResultRecovery` |
| Local rejection, disabling on an existing connection, request sizes and parameters | Same file: `TestLocalPolicyRevocationAndRequestLimits` |
| Enrollment retry, changed public-key rejection, same-key renewal and previous-certificate recovery | Same file: `TestEnrollmentRetryRenewalAndExpiredCertificate` |
| Wrong CA, wrong hostname, expired client-certificate handshake | Same file: `TestUntrustedServerAndExpiredTLSIdentity` |
| Concurrent duplicates, restart deduplication, interrupted UNKNOWN, persistence failure, output limits, exclusive lock | [engine_test.go](../internal/agent/engine_test.go) |
| Audit-failure rollback, expiry-state differences, audit retention, incompatible database rejection | [database_test.go](../internal/database/database_test.go) |
| Strict task parameters, metrics, SSH/service report validation | Tests under [protocol](../internal/protocol/) |
| Invalid local resources, links/path escapes/file replacement, credential reads | Tests under [policy](../internal/policy/), [saferead](../internal/saferead/), [localfile](../internal/localfile/) |
| Bounded collection and sensitive-content handling | Tests under [collectors](../internal/collectors/) |

The five-node integration test uses real TLS HTTP services and separate identities on one machine. It checks valid report shapes and the task workflow. Some collectors can legitimately return unavailable data, so successful task counts do not establish that every host resource was readable.

## Actual-binary acceptance

Run as an ordinary Linux user:

```sh
mkdir -p bin
for command in server agent argus; do
  CGO_ENABLED=0 go build -trimpath -o "bin/$command" "./cmd/$command"
done
python3 test/deployment/cli_smoke.py --bin ./bin
```

[cli_smoke.py](../test/deployment/cli_smoke.py) starts the real programs in temporary directories, enrolls five separate certificates, and runs 15 P0 tasks: `system.info`, `system.metrics`, and `service.status` on each node. It repeatedly runs agents with `-once`, restarts the server, reads existing results, and checks private backup-file creation. It also checks protocol/build observations, storage commands, private result export, discard confirmation and server-result preservation, and account revocation/roles after restart. It does not install system services. The script does not assert availability of every data field; database restoration is tested separately by integration tests.

The earlier local run recorded on 2026-11-04 completed all 15 tasks successfully and passed server/agent restart and backup checks. Total script time was 2.234 seconds; `batch_submit_to_inspection_seconds` was 1.173 seconds. The final refinement run also passed the added maintenance, storage, and account checks (total 1.577 seconds, batch 0.781 seconds). That batch field starts timing execution after enqueueing. It measures local sequential execution through inspection, not per-task network latency, throughput, or a production performance target.

## Fuzzing

The seven fuzz targets match CI:

```sh
go test ./internal/strictjson -run '^$' -fuzz '^FuzzDecode$' -fuzztime=10s -parallel=2
go test ./internal/protocol -run '^$' -fuzz '^FuzzDecodeTask$' -fuzztime=10s -parallel=2
go test ./internal/protocol -run '^$' -fuzz '^FuzzDecodeResult$' -fuzztime=10s -parallel=2
go test ./internal/protocol -run '^$' -fuzz '^FuzzDecodeMeasurements$' -fuzztime=10s -parallel=2
go test ./internal/enrollment -run '^$' -fuzz '^FuzzParseCSR$' -fuzztime=10s -parallel=2
go test ./internal/collectors/ssh -run '^$' -fuzz '^FuzzSSHParsers$' -fuzztime=10s -parallel=2
go test ./internal/collectors/services -run '^$' -fuzz '^FuzzDBusResponseGuard$' -fuzztime=10s -parallel=2
```

The initial local run used approximately three seconds and two workers per target. The refinement run passed all seven targets with ten seconds and two workers each, matching CI. These checks can detect concrete parser regressions but are not exhaustive security verification.

## CI and native deployment

[go.yml](../.github/workflows/go.yml) defines Linux/Windows builds, vet, unit/integration tests, and Linux race detection, vulnerability scanning, native systemd queries, fuzzing, and the five-agent CLI workflow.

A separate `deployment` job runs [systemd_smoke.py](../test/deployment/systemd_smoke.py) as root in a disposable Ubuntu 24.04 VM. The script requires `--disposable-ci`, `GITHUB_ACTIONS=true`, and no preexisting Argus installation. It writes `/etc` and `/var/lib` and starts services. Run it only in that disposable environment, not as a routine diagnostic on existing nodes.

It checks actual service users, `NoNewPrivileges`, `ProtectSystem`, memory limits, all six task types, available service/SSH reports with complete SSH coverage, and retained results after service restarts. It also mounts a dedicated 16 MiB tmpfs and runs `TestFilesystemFullRecovery` as a non-root user, then unmounts it. The test refuses a shared filesystem or a tmpfs larger than 32 MiB. The existence of the script and workflow does not prove a successful CI run; use the logs for the corresponding commit as evidence.

## Recorded local checks and remaining acceptance

Local checks recorded on 2026-11-04 passed build, vet, ordinary/race tests, Windows cross-build, short fuzz runs, native read-only systemd queries, and the actual CLI workflow. The local Windows check was cross-compilation, not execution of Windows tests.

The vulnerability scan on Go 1.27.3 reported zero reachable vulnerabilities, zero affected imported packages, and one unreachable advisory in a required module. This is a dated result, not a permanent vulnerability-free guarantee. The reachable X.509 issue GO-2026-6809 in Go 1.27.2 was addressed by updating the toolchain. Rerun the scan during maintenance.

Remaining VPS acceptance includes deployment on five authorized hosts, actual availability of P0 data, sustained operation, temporary disconnection and recovery, certificate renewal, isolated backup/restore exercises, and resource/latency measurements. Record hosts, OS versions, configuration, timestamps, outcomes, and limitations. Remote deployment and sustained production operation have not been validated.

## Documentation checks

Validate local Markdown links, fenced JSON, and shell syntax when editing examples. Compare API routes with [http.go](../internal/api/http.go), CLI flags with command help, and policy examples with `agent run -check`. Keep Chinese supplements aligned with their English counterparts, especially commands and configuration fields.

The local quick-start workflow has been exercised as a non-root user in temporary directories, covering builds, enrollment, both system task types, audit queries, and process shutdown. Configuration examples and the then-current CLI subcommand help outputs have also been checked. A backup check confirmed that `backup` works with service configuration whose systemd credential paths are inaccessible, because that command only needs configuration structure and database access.

These checks establish documentation usability; they do not replace the separately recorded unit, race, fuzz, or vulnerability checks.

## Reliability refinement evidence — 2026-11-04

Environment: Linux 7.0.0-34-generic, x86_64, Go 1.27.3, Python 3.14.4; temporary local state and a non-root agent. These records describe the working tree, not a published release or a remote CI result.

The implementation separates dispatch expiry, collection duration, and inferred result lateness; compares validated typed results; persists delivery dispositions; supports offline result maintenance; checks protocol/build metadata; verifies private backups; reports storage; and exposes listener coverage.

| Refinement | Repeatable evidence |
| --- | --- |
| Crash windows, failed RUNNING/result persistence, monotonic duration, local time skew | [recovery_test.go](../internal/agent/recovery_test.go): real child-process exits before/after acceptance, execution, persistence, and acknowledgment; no repeat collection after uncertainty |
| Same ID with changed assignment, concurrent duplicates and restart | [engine_test.go](../internal/agent/engine_test.go) |
| Typed result equivalence, exact large counters, array order, whitespace | [equivalence_test.go](../internal/protocol/equivalence_test.go) |
| Held results, discard/restart deduplication, atomic failure, UTF-8 and reserved capacity, 999/1000 boundary, actual `SQLITE_FULL` | [delivery_test.go](../internal/agent/delivery_test.go) |
| Export permissions, explicit confirmation, retry after discard | [maintenance_test.go](../cmd/agent/maintenance_test.go) and the actual-binary workflow |
| ACK loss, competing uploads and timeouts, scoped business errors, ten-second upload budget followed by heartbeat, compatibility on every request | [reliability_test.go](../test/integration/reliability_test.go) |
| Wrong-key renewal, expired-certificate offline maintenance and worker lock | [fleet_test.go](../test/integration/fleet_test.go) |
| Disable races with grant/renew/result; current/previous identity refusal; backup then disable then isolated restore and reapply revocation | [reliability_test.go](../test/integration/reliability_test.go) |
| Guarded transition rollback, deadlines, verified/nonoverwriting backups | [database_test.go](../internal/database/database_test.go) |
| Wrong schema/component rejection preserves existing records and foreign empty databases | [schema_test.go](../test/integration/schema_test.go) |

Build, vet, ordinary tests, full race tests, Windows cross-build, the seven ten-second fuzz targets, native read-only systemd queries, the current vulnerability scan, and the expanded five-agent binary workflow passed locally. Subsequent state-transition and schema changes also passed targeted race checks. Administrator-token verification reuses the existing authentication system and adds rotation/revocation, restart behavior, role, permissions, and log checks.

The environment-dependent deployment gap was closed for baseline `8fe8997` on 2026-11-05 by [run 41864153776](https://github.com/Oreki0504/Argus-C2/actions/runs/41864153776). Linux and Windows jobs and the deployment check completed successfully; [deployment check 126693853310](https://github.com/Oreki0504/Argus-C2/actions/runs/41864153776/job/126693853310) confirmed native service installation, collection/restarts, and `TestFilesystemFullRecovery` on an isolated 16 MiB tmpfs. SQLite `max_page_count` tests remain separate from this real ENOSPC test. The ordinary suite still skips filesystem exhaustion outside its dedicated disposable environment.

Five independent VPS instances remain deferred. Real deployment on those hosts, 72-hour operation, network disruption, actual renewal-window recovery, revocation, isolated restore, disk pressure, and measured resource/latency behavior are unverified. Five local identities and a short GitHub Actions run do not establish those results. In particular, default agent certificates live 30 days, so a new deployment's 72-hour run alone cannot exercise the seven-day renewal window; plan a separately authorized certificate-lifetime fixture or a later observation window.

## Current refinement coverage

The existing workflow runs the new regression tests without a separate testing framework:

| Change | Evidence |
| --- | --- |
| Middleware performs TLS identity/protocol checks without duplicate DB authorization | [http_test.go](../internal/api/http_test.go); existing integration disable/renew/grant/result races verify final transactional authorization |
| Manual 30-day server history cleanup | [retention_test.go](../internal/database/retention_test.go): cutoff, protected active/UNKNOWN records, bounded preview, backup restore, failed backup/audit/delete rollback, frozen/stale batches, late upload and grant rejection |
| CLI preview/apply boundary | [server retention tests](../cmd/server/retention_test.go): defaults, invalid arguments, service-credential independence, required backup and nonoverwrite; existing binary smoke checks default preview and protection of recent history |
| Partial collector output | [network tests](../internal/collectors/network/linux_test.go) and [process tests](../internal/collectors/process/linux_test.go): read errors after valid data, Scanner overflow, malformed rows, and cancellation |

That refinement kept both schemas at 101 and protocol at 1; no collector report fields or PKI implementation were introduced. The subsequent review fixes below move only the server database to Schema 102. Health semantics and Offline Root + Online Intermediate are documented against the current implementation, with the latter explicitly a future design.

Local verification on 2026-11-05 passed build, vet, all tests, full race tests, Windows cross-compilation, and the existing five-agent actual-binary workflow (15 P0 tasks, restart, backup, local maintenance, account revocation, storage). The binary workflow took 2.008 seconds, including 0.974 seconds for its batch execution/inspection measure; these are local observations, not VPS performance targets. All 14 Markdown documents were checked for local links/anchors, fenced JSON, and shell syntax. The final network-cancellation adjustment passed targeted race checks, and the binary smoke also passed the added default-preview/backup/recent-history assertions. The vulnerability scan found zero reachable vulnerabilities (one advisory in an unused part of a required module). Native Windows execution and disposable systemd/ENOSPC acceptance of this change require its new GitHub Actions run.

## Maintaining documentation with code

Update [cli.md](cli.md) when changing command arguments; [configuration.md](configuration.md), [api.md](api.md), and relevant schemas when changing fields or limits; [collectors.md](collectors.md) when changing reports; and [architecture.md](architecture.md) and [operations.md](operations.md) when changing state or recovery behavior. Update this page from actual test records, and describe planned behavior as pending until implemented and verified.

## Review follow-up coverage

The review of `9c77f2b` led to Server Schema 102 (Agent Schema 101 and protocol 1 remain). The preceding baseline passed [run 42018199745](https://github.com/Oreki0504/Argus-C2/actions/runs/42018199745); the changes below require their own commit-specific CI result.

| Review concern | Regression evidence |
| --- | --- |
| Failed execution grant without future redelivery | [authorization_test.go](../internal/agent/authorization_test.go) and [grant_recovery_test.go](../test/integration/grant_recovery_test.go): explicit denial, timeout, dropped grant response, server expiry, persistence barrier, capacity reservation, restart/no recollection |
| Renewal outage while certificate is valid | [renewal_availability_test.go](../test/integration/renewal_availability_test.go): result upload, heartbeat and new work continue, retries are spaced, disabling remains enforced; [runner_test.go](../internal/agent/runner_test.go) rejects expired identity before network use |
| Success requires prior execution authorization | [lifecycle_test.go](../internal/database/lifecycle_test.go): ACCEPTED success refusal, authorized/unauthorized UNKNOWN late reports, retained grant timestamp |
| Trusted retention and bounded UNKNOWN history | Same lifecycle tests: old/future completion claims, first receipt immutability, 30/90-day boundaries, late receipt invalidates frozen cleanup, task_not_found after prune |
| Server Schema 101 incompatibility | [schema_test.go](../test/integration/schema_test.go): current-1/current+1 and foreign component rejection preserve state |
| Newest task pages and standard JSON Content-Type | [task_query_test.go](../internal/database/task_query_test.go), [web_api_test.go](../test/integration/web_api_test.go): same-second ordering, cursor/filter binding, concurrent inserts, ReadOnly query, malformed bounds/media types |
| Server certificate lifecycle | [certificates_test.go](../cmd/server/certificates_test.go) and [server_rotation_test.go](../test/integration/server_rotation_test.go): public-file monitoring, expiring/expired/future validity, same-root leaf/key replacement, reconnect and pending result upload |

The existing workflow discovers these Go tests; the actual-binary smoke covers the added CLI commands. No Web Session or Frontend implementation is claimed. Five-host/72-hour acceptance remains deferred; GitHub Actions covers the current disposable deployment stage.

Local verification of this review follow-up on 2026-11-05 passed build, vet, all tests, full race tests, Windows cross-compilation, and govulncheck (zero reachable vulnerabilities; one advisory in an unused part of a required module). The existing five-agent binary workflow passed all 15 P0 tasks plus pagination, certificate monitoring, retention preview, backup, restart, maintenance, and account checks (3.773 seconds total; 1.579 seconds for its batch observation, not a fleet performance claim). The final pruned-UNKNOWN/held-result TLS regression also passed with race detection. All 15 Markdown files passed local-link/anchor and fenced JSON/shell checks. Native Windows execution and systemd/ENOSPC validation remain commit-specific GitHub Actions checks.

## Console monitoring and maintenance — 2026-11-08

Local checks for the preview.10 working tree passed the full Go suite and vet; focused Console/database race tests; frontend typecheck, lint and unit tests (20 passed, one contract-fixture check skipped without its CI fixture); and 61 isolated installer/update/uninstaller tests using a built amd64 bundle. Browser coverage passed 32 cases, with the real-HTTPS fixture case skipped outside its dedicated environment. The new GitHub error-page test was rerun successfully after fixing its mock login scenario.

New regressions cover idle-queue collection, manual-work precedence, rate limiting after policy rejection, disabled-node refusal, default-route interface selection, counter reset/gap handling, indexed recent network observations, GitHub error classification and secret suppression, and OAuth configuration versus personal identity linking. GitHub tests use a controlled provider; the reported live GitHub failure remains unconfirmed until the affected deployment retries with the new diagnostics.

The disposable native installer test now requires Console on 443 as `argus-server`, real automatically collected CPU/memory/disk/system data, two network samples, and Agent purge removing configuration, service files and the dedicated account while Server stays active. This native check runs in Actions, not on the developer machine. Existing deployment updates retain their ports and identities. Five-host sustained acceptance remains deferred.

## Agent management and login controls — 2026-11-09 (Asia/Tokyo)

Local preview.11 checks passed the full Go suite and vet, focused Console/database race tests, frontend typecheck/lint and unit tests, and 61 isolated installer/update/uninstaller tests against the built amd64 bundle. Both Linux architecture bundles built successfully. The browser suite passed 33 cases; the real-HTTPS case passed separately against the Go harness, including Token login, OAuth linking, Token disabling and continued authenticated management.

New backend regressions verify public rename projection, User/anonymous denial, exact-ID deletion and CSRF, atomic rollback on audit failure, dependent-history removal and old-certificate refusal. Token tests require recent successful OAuth verification, revoke token-only sessions and stale binding/write authority, reject removal of the last linked login provider, and verify disabled-token persistence with working OAuth after restart. Callback tests keep Cookie/state/provider/PKCE checks intact and reject invalid flows before exchanging a code. Browser tests exercise rename/delete, public-list refresh and disabled-token login presentation.

The live GitHub deployment's failure is not yet reproduced. Its observed authorization redirect targets the expected GitHub endpoint with S256 PKCE, `read:user` and the configured Console callback; that alone does not verify the callback. New fixed reason codes diagnose the remaining stages without logging callback credentials. No live GitHub root-cause fix is claimed. Native installation, Windows and full release validation remain commit-specific Actions checks.

## GitHub authorization issuer correction — 2026-11-09 (Asia/Tokyo)

The deployment subsequently returned `oauth_issuer_mismatch`. GitHub's public [authorization-server metadata](https://github.com/login/oauth/.well-known/openid-configuration) identifies its issuer as `https://github.com/login/oauth`; ARGUS had incorrectly compared it with the persistent `https://github.com` account namespace. Adding that issuer to the provider fixture reproduced the exact `/account?reason=oauth_issuer_mismatch` failure in the existing linking test before the correction.

The corrected implementation validates the authorization issuer separately without changing stored identities or credentials. The same linking test now passes. Regressions cover setup/login/binding, restart and stable identity after callbacks without `iss`, plus rejection of wrong, empty, duplicate and trailing-slash issuer values before code exchange. The full Go suite, vet and focused Console race tests passed locally. Schema versions and protocol are unchanged. A real user retry remains the final deployment check; simulated OAuth tests do not authorize a live GitHub account.

The separately reported browser security warning was not reproduced on the public Console: verified curl TLS and a clean Chromium 158 session accepted the certificate, and all loaded page/API resources reported `secure` over HTTPS. This confirms the inspected connection only; the affected browser's exact warning remains necessary to explain its displayed state.

## Console UI redesign — 2026-11-09 (Asia/Tokyo)

Local preview.13 checks passed frontend typecheck, ESLint, Prettier, Vitest unit and contract tests, and production bundle compilation. Overview, Server Detail, Traffic, Management (Tasks, Agents, Audit, Users & access), Account & sign-in, and Setup now share a monochrome Geist palette, four-card Bento summary row, compact strip/card view toggle, multi-metric sorting, severity-based utilization meters, equal-height offline cards, and interactive SVG history charts without native range sliders. Backend APIs, database schemas (Server 104, Agent 101) and wire protocol 1 are unchanged.

