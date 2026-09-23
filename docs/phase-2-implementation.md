**Argus-C2: Phase 2 Implementation**

Phase 2 provides an executable, loopback-only development foundation: a Go module, strict shared protocol types, task-envelope signatures, locally provisioned node identities, and a mutually authenticated TLS connection check. It does not yet execute or collect tasks. The [Phase 1 design](phase-1-design.md) remains the target architecture; this document distinguishes the implemented subset from later work.

**Toolchain and layout**

The module is `github.com/Oreki0504/Argus-C2`. The baseline and CI toolchain is Go 1.27.1, selected from the [official release history](https://go.dev/doc/devel/release). Application code uses only the standard library; there are no external runtime modules and no go.sum is required. To reproduce the exact local toolchain, set `GOTOOLCHAIN=go1.27.1` in your shell; otherwise Go's toolchain selection may use a newer installed version.

| Path | Implemented responsibility |
| --- | --- |
| `cmd/server` | Loopback mTLS identity-check server |
| `cmd/agent` | One-shot probe connection check |
| `cmd/devpki` | Local, short-lived development credentials; never a network CA |
| `internal/strictjson` | Bounded JSON parsing, duplicate/unknown-field and Unicode checks |
| `internal/protocol` | Task, result, error, and connection-response types; task preflight |
| `internal/signing` | Fixed-domain Ed25519 envelopes over original payload bytes |
| `internal/identity` | Node IDs, canonical certificate URI, local registration and disablement |
| `internal/localfile` | Bounded reads of trusted local configuration and private keys |
| `internal/tlsconfig` | Required TLS 1.3, explicit CA trust, peer validation |
| `internal/server`, `internal/agent` | Minimal HTTP server and outbound client |
| `schemas` | Versioned task and signature-envelope JSON Schemas |
| `test/integration` | Real TLS connections with positive and negative cases |

The administration CLI is deferred to Phase 6. `cmd/agent` is the resident-client entry point, currently limited to one connection check; it does not install a service or run a background loop.

**Try the connection locally**

Run these commands from the repository root with Go 1.27.1 available. They work in PowerShell and a POSIX shell. On Linux, run as an unprivileged user; the server and probe commands refuse UID 0. The generated `.local/` directory is ignored by Git.

1. Generate fresh development credentials in a new directory:

```text
go run ./cmd/devpki -out .local/dev-pki
```

The command creates a new CA, a server certificate valid for localhost/loopback addresses, one probe identity and certificate, and a matching local registry. Certificates last 24 hours. It refuses an existing output directory and never saves the CA private key. Choose a different output directory for another run and adjust subsequent paths accordingly.

2. Start the server in one terminal:

```text
go run ./cmd/server -listen 127.0.0.1:8443 -cert .local/dev-pki/server-cert.pem -key .local/dev-pki/server-key.pem -ca .local/dev-pki/ca.pem -registry .local/dev-pki/registry.json
```

3. Run the probe in a second terminal:

```text
go run ./cmd/agent -server https://127.0.0.1:8443 -cert .local/dev-pki/probe-cert.pem -key .local/dev-pki/probe-key.pem -ca .local/dev-pki/ca.pem -identity .local/dev-pki/identity.json
```

Success prints a JSON object with version 1 and the authenticated `agent_id` and `enrollment_epoch` from identity.json. The probe then exits. Stop the server with Ctrl+C.

Development certificates and private keys are local test material, not production credentials. On Unix, private-key files with group/other permission bits are rejected. On Windows, the loader does not claim to validate NTFS ACLs; protect the development directory with the operating system's access controls. Configuration files and their parent directories must be locally trusted. The local configuration reader is not the future remote log/file access implementation.

**Identity and authorization**

Node IDs and enrollment epochs are each 16 random bytes encoded as exactly 32 lowercase hexadecimal characters. A probe certificate must have exactly one URI SAN:

```text
argus://nodes/<agent_id>/epochs/<enrollment_epoch>
```

The parser rejects alternate schemes, user information, query strings, fragments, escaped aliases, extra path components, and multiple URI SANs. Probe leaf certificates must have only the clientAuth extended key usage and must not be CA certificates. Common Name is not an identity source.

The locally supplied registry binds the node ID, epoch, exact certificate SHA-256 fingerprint, and enabled state. Sharing a trusted issuer does not grant access. Both TLS handshakes and HTTP requests recheck the registry, and requests recheck the verified certificate chain's validity dates. Disabling a node through the in-process registry rejects further requests, including requests on an existing connection. There is no remote disablement API, automatic registry-file reload, durable registry mutation, or certificate-renewal flow yet; file changes take effect after a server restart.

The only endpoint is `GET /api/v1/agent/identity`, behind mandatory mTLS. It returns the caller's certificate-bound identity, accepts no body or query parameters, and sends `Cache-Control: no-store`. Unknown paths and methods are rejected. The server requires a literal loopback listening address. No administrator or task-dispatch API is exposed in this phase.

**Transport behavior**

- TLS 1.3 is required at both ends, with normal X.509 chain, validity, usage, and server-name verification.
- Trust roots are explicitly loaded from a nonempty CA PEM bundle; platform trust is not a fallback. Local certificate/private-key mismatches fail startup.
- TLS session tickets are disabled on the server, and the probe has no session cache.
- The probe accepts only an HTTPS origin, sends no identity in an overrideable request field, ignores environment proxy settings, and refuses all redirects.
- Connection, handshake, response, and server-request deadlines are bounded. Identity responses are limited to 4 KiB and must match the probe's own identity and epoch.

**Protocol foundation**

Phase 2 recognizes only `system.info` and `system.metrics` task shapes, each version 1 with an empty parameter object. These are data contracts without executable handlers. All other task names are rejected. Shared result types reserve the planned fields; no result-ingestion endpoint or task-specific result validators exist yet.

The strict decoder rejects missing/unknown fields, case variants, duplicate keys at any depth, trailing JSON, null, invalid UTF-8, unpaired UTF-16 escapes, wrong field types, excessive nesting, and oversized input. Integer fields reject fractional and exponent encodings. Tasks require canonical IDs, an actor identifier, a policy digest, and a positive, ordered validity window of at most 300 seconds.

Task preflight checks validate the expected node, epoch, policy digest, expiration, and maximum 30-second future creation skew. They do not authorize execution, check local resource allowlists, or persist replay state.

Signature verification uses the original payload bytes prefixed with `argus-c2/task/v1` and a NUL separator. Envelopes require canonical, unpadded Base64URL and a 64-byte Ed25519 signature. There is no selectable algorithm or verification-bypass mode. A valid signature does not override local policy or make a compromised signing server trustworthy. Signing utilities are exercised locally and are not exposed by the development endpoint.

The JSON Schemas describe supported message shapes. Byte limits, duplicate keys, Unicode and exact-number encoding rules, cross-field validity windows, cryptographic checks, and contextual preflight are additionally enforced in Go. Server and probe share the same decoder rather than maintaining independent validation implementations. Persistent anti-replay storage and dispatch gates remain Phase 4 work.

**Validation**

```text
go test ./... -count=1
go vet ./...
go build ./...
go test -race ./... -count=1
```

The race detector requires a supported platform and C compiler; CI runs it on Linux. Unit and TLS integration tests run on Linux and Windows. CI actions are pinned to commit hashes and have read-only repository permissions.

The Linux job also runs `go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...` against the current Go vulnerability database. This separately versioned development tool is not an application dependency.

Bounded fuzz smoke tests:

```text
go test ./internal/strictjson -run '^$' -fuzz '^FuzzDecode$' -fuzztime=10s -parallel=2
go test ./internal/protocol -run '^$' -fuzz '^FuzzDecodeTask$' -fuzztime=10s -parallel=2
go test ./internal/signing -run '^$' -fuzz '^FuzzVerify$' -fuzztime=10s -parallel=2
```

Coverage includes missing/untrusted/expired/future client certificates, invalid usages and identities, same-CA unregistered certificates, wrong epochs, disabled nodes on reused connections, rejected TLS 1.2, invalid server certificates and hostnames, redirects, oversized or mismatched identity responses, strict task parsing, signature tampering, and noncanonical encodings. Unix-specific tests additionally check private-key permissions and symlink rejection. Test credentials are generated at runtime; no fixture private keys are committed.

The next stage adds explicit one-time enrollment, heartbeats, and system information/metric collection. Production service installation, privileged helpers, live administrator authentication, durable audit storage, and deployment hardening are not implemented here.
