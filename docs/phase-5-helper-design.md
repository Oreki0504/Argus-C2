# Read-only SSH Helper: Design and Review Gate

Status: design constraints only. No helper executable, privileged service, sudo rule, setuid binary, capability grant, installation script, or helper IPC exists in Phase 5. The non-root probe reports explicit coverage gaps for resources it cannot read. This document does not authorize or certify a future helper implementation.

## Why a separate boundary may be needed

A dedicated probe account may read a host's SSH configuration but cannot normally traverse another user's private `.ssh` directory. Expanding the main probe's privileges would put its TLS, parsing, queue, and storage code inside that larger authority. A future helper would need a separate review and an explicit local administrator decision before accessing any additional resource.

The current collectors already return `permission_denied` and unavailable coverage. That is the implemented behavior. Do not relax SSH directory permissions, run the probe as root, or introduce a generic `sudo cat`, `sshd`, shell, or `systemctl` escape to fill the gap.

## Requirements before implementation

1. Define a fixed, versioned local IPC request for a logical profile ID. No client-supplied paths, commands, unit operations, arbitrary file descriptors, or writable handles. Authenticate the exact local caller through OS peer credentials and a root-controlled socket, with bounded framing and connection quotas.
2. Keep root-owned policy and its parent directories independent of the probe's writable state. The helper's authority must be an explicit subset of the node's approved SSH mappings. It must never accept a policy replacement, baseline update, or path expansion from the probe or server.
3. Review whether a signed task, local-policy binding, independent replay/rate state, and audit intent must be verified by the helper itself. Caller identity alone is insufficient to establish task authorization when the caller can be compromised. Specify crash recovery and durable audit failures before permitting privileged collection.
4. Pin and validate directory/file descriptors, exact ownership, file type, link count, mount boundaries, byte limits, and before/after identity. Reject unsafe kernel/filesystem conditions without falling back to broad reads. Validate resource replacement on every request rather than relying on a startup-only check.
5. Return only bounded typed observations: fingerprints, approved directive/value pairs, metadata, comparison outcomes, and explicit gaps. Never return raw files, private keys, key options/comments, arbitrary configuration values, secrets, or usable descriptors to the probe. Treat file bytes as untrusted parser input.
6. Provide process isolation, syscall restrictions, filesystem isolation, no network access, no process execution, no mutable service controls, minimal capabilities, and strict resource budgets appropriate to the actual implementation. Define upgrade, rollback, revocation, shutdown, and operator-visible audit procedures.
7. Test malicious authorized callers, oversized/fractured messages, concurrent requests, socket spoofing, symlink/hard-link/mount substitution, file rotation, parser denial of service, crash recovery, audit/storage exhaustion, and policy changes. Include an independent review of all privileged paths before documenting an installation procedure.

The helper must remain absent until its narrow interface, privilege requirements, operational controls, and adversarial tests satisfy that review. Service status currently uses an ordinary non-root read-only D-Bus client and does not require a helper.
