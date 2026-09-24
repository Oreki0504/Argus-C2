**Argus-C2: Phase 3 Enrollment and Telemetry**

Phase 3 implements explicit registration, persistent identity authorization, outbound heartbeats, and native Linux collectors for `system.info` and `system.metrics`. Collection is initiated by the probe's local configuration. There is no remote task dispatch or command-execution endpoint. Both server listeners remain restricted to literal loopback addresses until the later administrator authentication, audit, and deployment phases are complete.

The [Phase 1 design](phase-1-design.md) remains the target architecture. The [Phase 2 static-registry connection check](phase-2-implementation.md) remains available without enabling telemetry or enrollment.

**Implemented components**

| Component | Behavior |
| --- | --- |
| `cmd/devpki -enrollment` | Generates short-lived local development transport and issuing credentials; never saves the root CA key |
| `cmd/localctl` | Local token creation, snapshot inspection, and node disablement through direct database access |
| `cmd/enroll` | Reads a token from stdin, generates a local Ed25519 key, submits a signed CSR, and verifies the issued identity |
| `cmd/server -state` | Uses a persistent SQLite registry and accepts authenticated heartbeats |
| `cmd/server -enroll-listen` | Explicitly enables a separate TLS enrollment listener |
| `cmd/agent -config` | Samples the locally configured scope and sends mTLS heartbeats; `-once` sends one report |
| `internal/collector` | Native Linux system information, CPU, memory, disk, and network collectors; explicit unavailable values elsewhere |
| `internal/state` | Versioned SQLite schema, atomic token consumption and registration, latest-report storage, persistent disablement |

`localctl` is a development bootstrap tool, not the authenticated administration CLI planned for Phase 6. It requires local access to the server's private state directory. No management HTTP API has been added.

**Try the complete flow locally**

Use Go 1.27.1 and run from the repository root. On Linux, use a non-root account for every command: the server, probe, enrollment client, and local operator tool refuse UID 0. The examples keep all development material inside the ignored `.local/` directory. Use new output paths for subsequent PKI or enrollment runs; existing credentials are never overwritten.

1. Create development credentials:

```text
go run ./cmd/devpki -enrollment -out .local/phase3-pki
```

This generates `ca.pem`, `server-cert.pem`, `server-key.pem`, `issuer-cert.pem`, and `issuer-key.pem`. The root CA key exists only during this local command. The separately saved online issuer is constrained to client authentication and cannot issue subordinate CAs. Development root, issuer, and server certificates last 24 hours; issued probe certificates last at most 12 hours and never outlive the issuer. These deliberately short development lifetimes differ from the production lifecycle proposed in Phase 1. Automatic renewal is not implemented.

2. Start the server in one terminal:

```text
go run ./cmd/server -listen 127.0.0.1:8443 -enroll-listen 127.0.0.1:8444 -cert .local/phase3-pki/server-cert.pem -key .local/phase3-pki/server-key.pem -ca .local/phase3-pki/ca.pem -issuer-cert .local/phase3-pki/issuer-cert.pem -issuer-key .local/phase3-pki/issuer-key.pem -state .local/phase3-server
```

Port 8443 requires mTLS. Port 8444 verifies the server to a probe using its preinstalled CA, then checks a one-time token and CSR. The enrollment listener has no identity-query, heartbeat, or management route. Omit `-enroll-listen`, `-issuer-cert`, and `-issuer-key` to run only the enrolled-probe API after registration.

3. In another terminal, create and use a token without putting its value into command-line arguments or shell history.

PowerShell:

```powershell
$enrollmentToken = go run ./cmd/localctl -state .local/phase3-server -action token
if ($LASTEXITCODE -ne 0) { throw 'Token creation failed' }
try {
    $enrollmentToken | go run ./cmd/enroll -server https://127.0.0.1:8444 -ca .local/phase3-pki/ca.pem -out .local/phase3-probe
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed; inspect state before retrying' }
} finally {
    $enrollmentToken = $null
}
```

POSIX shell:

```sh
go run ./cmd/localctl -state .local/phase3-server -action token |
  go run ./cmd/enroll -server https://127.0.0.1:8444 -ca .local/phase3-pki/ca.pem -out .local/phase3-probe
```

The token has 256 random bits, defaults to ten minutes, and may be shortened with `-ttl`, up to a maximum of fifteen minutes. Only its SHA-256 digest is stored. The token appears only on the local tool's stdout; keep that stream private. For separately administered hosts in a later deployment, distribute trust anchors and the token through an authenticated manual channel. This prototype does not expose non-loopback server listeners.

Enrollment prints the assigned `agent_id` and `enrollment_epoch`, and creates `probe-key.pem`, `probe-cert.pem`, and `identity.json` in the new probe directory. The private key is generated locally and is never sent to the server. `identity.json` is written last as the completion marker.

4. Review [examples/telemetry.json](../examples/telemetry.json) and explicitly select the resources to report:

```json
{
  "interval_seconds": 30,
  "sample_milliseconds": 1000,
  "disk_paths": ["/"],
  "network_interfaces": ["lo"]
}
```

The example reports the root filesystem and loopback interface. Replace the interface with the locally approved name if needed. Empty arrays disable disk and network reporting respectively. Neither array is discovered or expanded by the server. Configuration is loaded once at startup; changing it requires a local restart.

5. Send one heartbeat:

```text
go run ./cmd/agent -server https://127.0.0.1:8443 -cert .local/phase3-probe/probe-cert.pem -key .local/phase3-probe/probe-key.pem -ca .local/phase3-pki/ca.pem -identity .local/phase3-probe/identity.json -config examples/telemetry.json -once
```

Remove `-once` to run continuously. Omit both `-config` and `-once` to retain the Phase 2 one-shot identity check. Continuous operation waits the configured interval with 10% jitter after each successful iteration. Failures use exponential backoff starting at five seconds, capped at five minutes including jitter. Sampling and uploads are sequential, so slow collection does not create overlapping work or an unbounded queue. Ctrl+C stops the process.

6. Inspect the stored observation:

```text
go run ./cmd/localctl -state .local/phase3-server -action nodes
```

The JSON includes registration state, enrollment time, the server receipt time in Unix nanoseconds, and the latest heartbeat. An enrolled node with no heartbeat has receipt time zero and a null heartbeat. Reports are observations supplied by that node; mTLS establishes who sent them, not their truthfulness. There is no historical time-series store or signed task-result ingestion yet.

7. Disable a test node using its printed ID:

```text
go run ./cmd/localctl -state .local/phase3-server -action disable -agent-id REPLACE_WITH_AGENT_ID
```

The next request is rejected even on an established connection. Disablement and the latest heartbeat survive server restarts. There is no automatic re-enable or remote enrollment retry.

**Enrollment and storage boundaries**

The server accepts only a valid Ed25519 CSR with proof of private-key possession and no supplied subject, SAN, attributes, or extensions. It chooses the node ID and enrollment epoch and fixes the leaf certificate to client authentication. The probe independently verifies the returned certificate against its own key, assigned identity, limited issuer, and preinstalled root. A response cannot install a new trust anchor, redirect the probe, select a proxy, or supply configuration.

Token consumption and registration insertion share one SQLite transaction. Concurrent uses through separate database connections can create only one registration. An insertion failure rolls back token consumption. The server sends the certificate only after a successful commit. This is atomic registration, not a guarantee that the client receives the response.

If a connection drops after commit, or a local credential write fails, the token may already be consumed. Enrollment is deliberately not retried automatically. Keep the partial probe directory for inspection; use `localctl -action nodes` to inspect newly enrolled identities, disable the orphaned identity, and issue a fresh token into a new local directory. Expired certificates also require explicit disablement and fresh enrollment. Renewal, recovery automation, and durable security audit history are later work.

SQLite uses WAL mode, full synchronous commits, a two-second busy timeout, parameterized queries, and one database connection per process. Schema version 1 is installed transactionally at local startup; unknown schema versions are rejected. At most 1,000 nodes and 1,000 outstanding tokens are retained. Expired or consumed tokens are pruned when issuing a token. Each node has only one stored heartbeat, with successful writes no more often than every five seconds. These bounds limit retained rows and write frequency, not all possible denial-of-service effects or filesystem usage.

The state directory must be operator-controlled. Unix state directories and database/key files reject group or other access; newly created directories use mode 0700 and files use 0600. Symlink database files and sidecars are rejected. Parent directories remain a trusted local-administration boundary. Windows is supported for development transport/storage testing, but this implementation does not validate NTFS ACLs or provide Linux metric collection. Protect the development directories with local Windows access controls. No generated keys, tokens, databases, or telemetry are committed to Git.

**Telemetry meaning and limits**

| Field | Source and meaning |
| --- | --- |
| System information | Runtime OS/architecture, hostname, `/proc/sys/kernel/osrelease`, and `/proc/stat` boot time |
| CPU busy percent | Two aggregate `/proc/stat` samples; idle and iowait count as idle; guest fields are not double-counted |
| Memory | `/proc/meminfo` MemTotal and MemAvailable, converted from KiB to bytes |
| Disk | `statfs` on each locally configured path; total and bytes available to an unprivileged user |
| Network | `/proc/net/dev` receive/transmit byte counters for each locally configured interface; cumulative counters, not bytes per second |

Missing, malformed, overflowing, unsupported, or inaccessible measurements use `available: false` with zero measurement fields. A zero value with `available: false` is not a healthy empty system. Unsupported platforms retain runtime OS/architecture and resource identifiers while reporting measurements unavailable. CPU sampling resets and backwards counters are also unavailable rather than negative usage.

The local interval is 10-300 seconds, CPU sampling is 100-5,000 milliseconds, and allowlists have at most eight disk paths and sixteen interfaces. Paths must be canonical absolute Linux paths; resources are never taken from heartbeat acknowledgments. Fixed proc reads are individually bounded. No shell, subprocess, uploaded code, environment-variable collection, process-memory read, or privileged helper is used.

The collection loop uses a ten-second context deadline and checks cancellation between operations. A kernel filesystem call such as `statfs` cannot be interrupted reliably by a Go context. Choose known local filesystems; a stalled network/FUSE mount may delay that one probe. Process isolation and deployment resource controls remain Phase 7 work.

Heartbeats are limited to 16 KiB with strict exact nested schemas. The server checks both identity and epoch against the current mTLS registration, checks the verified certificate chain on every request, and accepts observation times only from five minutes in the past through thirty seconds in the future. Acknowledgments contain only version and the same identity. They cannot carry tasks, URLs, resource changes, or scheduling hints. Duplicate observation submissions within the minimum write interval are rejected; persistent task replay prevention and policy digests remain Phase 4 work.

Enrollment requests and replies are limited to 8 KiB; DER CSRs to 2 KiB. Enrollment allows four simultaneous handler operations and thirty attempts per minute per server process. Probe handlers allow thirty-two concurrent operations. Both listeners have HTTP timeouts, reject compressed/chunked request bodies and query parameters, and expose only their fixed routes. These are development limits, not a production internet-facing admission-control design.

**Dependencies and validation**

Go 1.27.1 remains the pinned baseline. [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) supplies pure-Go SQLite without a C runtime build requirement; `golang.org/x/sys/unix` supplies Linux filesystem statistics. Direct and transitive versions and checksums are recorded in go.mod/go.sum. No extensions or dynamic SQL are supplied by network requests.

```text
go build ./...
go vet ./...
go test ./... -count=1
go test -race ./... -count=1
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

The race detector runs on Linux with a supported compiler. CI also tests Windows; Linux exercises real proc/statfs collectors and Unix permissions, while Windows verifies unavailable collector behavior. New tests cover concurrent one-time tokens, expiration, rollback, restart persistence, unsupported schemas, CSR tampering, locally bounded sampling, heartbeat impersonation, live disablement, listener separation, and hostile enrollment replies. Real TLS integration tests complete enrollment and then submit a stored heartbeat.

CI adds bounded fuzz smoke tests for heartbeat decoding and CSR parsing to the existing strict JSON, task, and signature suites:

```text
go test ./internal/protocol -run '^$' -fuzz '^FuzzDecodeHeartbeat$' -fuzztime=10s -parallel=2
go test ./internal/enrollment -run '^$' -fuzz '^FuzzParseCSR$' -fuzztime=10s -parallel=2
```

JSON Schemas in `schemas/` document enrollment and heartbeat shapes. Runtime checks additionally enforce byte bounds, canonical encodings, duplicate keys, Unicode, numeric and availability relationships, certificate validity, and identity binding. Passing this phase does not establish the full server-compromise containment claim: Phase 4 must add independently enforced execution policy, task dispatch gates, persistent replay state, and auditing before any remote task interface is enabled.
