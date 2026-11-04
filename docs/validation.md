# Development and validation

[Documentation](../README.md) · [Architecture](architecture.md) · [Deployment](deployment.md)

Argus-C2 is under development and has not reached an MVP release. This page distinguishes test coverage, recorded local runs, and acceptance still requiring another environment. The local regression checks below passed. Actual filesystem exhaustion and native service deployment still require the disposable deployment job; sustained acceptance on five independent Linux VPS instances remains pending until test hosts are available.

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

Two environment-dependent items remain open:

1. **Actual filesystem ENOSPC and native service deployment.** `TestSQLiteFullBeforeAcceptanceNeverCollects` passed using SQLite's real `max_page_count` exhaustion, and trigger-injected failures cover persistence windows. These are separate from [disk_linux_test.go](../internal/agent/disk_linux_test.go), which is wired into the disposable deployment job but has not been executed here. This host cannot create the required isolated mount without interactive privileged access. The ordinary suite skips that test; no host disk was filled, and live read-only systemd queries do not prove service deployment.
2. **Five independent VPS instances.** Hosts have not been supplied. Real deployment, sustained operation (proposed first window: 72 hours), network disruption, actual renewal-window recovery, revocation, isolated restore, disk pressure, and measured resource/latency behavior remain unverified. Five local identities are not five VPS instances.

## Maintaining documentation with code

Update [cli.md](cli.md) when changing command arguments; [configuration.md](configuration.md), [api.md](api.md), and relevant schemas when changing fields or limits; [collectors.md](collectors.md) when changing reports; and [architecture.md](architecture.md) and [operations.md](operations.md) when changing state or recovery behavior. Update this page from actual test records, and describe planned behavior as pending until implemented and verified.
