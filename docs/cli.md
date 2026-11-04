# CLI reference

[Documentation](../README.md) · [Configuration](configuration.md) · [HTTP API](api.md)

The programs are `server`, `agent`, and `argus`. The tables below list arguments that affect each subcommand. The shared argument parsers may accept some unrelated flags without giving them additional behavior.

## Argument order

```text
server <subcommand> [arguments]
agent  <subcommand> [arguments]
argus  [connection arguments] <subcommand> [subcommand arguments]
```

For `argus`, put `-server`, `-ca`, and `-token-file` **before** the subcommand. Other positional arguments are rejected: use `-node ID` or `-task ID`, not a bare trailing ID. `-h` prints the relevant help; the current entry points treat the help return as an error and exit 1.

## server

| Subcommand | Arguments | Behavior |
| --- | --- | --- |
| `init` | Required `-dir PATH`; `-hosts localhost,127.0.0.1`; `-listen 127.0.0.1:8443` | Create credentials, configuration, an administrator token, and SQLite state in a new directory |
| `run` | `-config /etc/argus-c2/server.json`; optional `-check` | Serve HTTPS; `-check` exits after loading the database, accounts, and credentials without binding a port |
| `backup` | `-config /etc/argus-c2/server.json`; required `-out PATH` | Create a consistent database snapshot without overwriting an existing file; verify integrity/schema and sync it |
| `storage` | `-config /etc/argus-c2/server.json` | Report database/WAL sizes, filesystem space, and warnings without loading service credentials |

`-hosts` is a comma-separated certificate DNS/IP list. `-listen` writes the initial configuration; when running, the address comes from the JSON `listen` field.

Initialization creates `ca.pem`, `ca-key.pem`, `server.pem`, `server-key.pem`, `admins.json`, `admin.token`, `server.json`, and `state/argus.db`. The initial administrator is named `admin` and has the `Admin` role.

`backup` validates the complete configuration structure and opens the database, but does not load the administrator file or TLS/CA private keys. It can use the normal service configuration when invoked by a user with access to the state directory. Use a private output directory, preferably mode 0700; the output file is created exclusively with mode 0600. A failed backup may leave an incomplete output file; treat only a successful command as a verified snapshot. Credentials and configuration are not part of the snapshot.

## agent

| Subcommand | Arguments | Behavior |
| --- | --- | --- |
| `enroll` | `-config /etc/argus-c2/agent.json`; required `-token-file PATH` | Generate or reuse a local key, enroll, and establish persistent identity state |
| `run` | `-config /etc/argus-c2/agent.json`; optional `-once` or `-check` | Run continuously; `-once` performs one cycle; `-check` validates configuration and policy only |
| `renew` | `-config /etc/argus-c2/agent.json` | Request renewal using the current certificate and original key; the server returns the current certificate outside the renewal window |

Local maintenance also uses `-config`:

| Subcommand | Arguments | Behavior |
| --- | --- | --- |
| `results` | Optional `-after ID` | List at most 200 local records with task ID, execution/delivery state, reason, and result bytes |
| `result-export` | `-task ID -out PATH` | Export the original report to a new private file |
| `result-retry` | `-task ID` | Return a held report to pending; cannot reconstruct discarded contents |
| `result-discard` | `-task ID`; optional `-confirm-task ID` | Display local status and consequences, require matching confirmation, remove report contents while retaining deduplication |
| `storage` | No extra arguments | Report database/WAL/filesystem space plus pending/held count, reserved bytes, and held/discarded counts |

Stop the agent before maintenance: all these commands require the existing exclusive state lock. They work offline with expired certificates, still verify the local key pair and stored identity, and do not query server state. Discard is a local disposition, not server acknowledgment or cancellation. Without `-confirm-task`, type the task ID at the confirmation prompt.

Enrollment, execution, renewal, and maintenance require Linux and reject root. Configuration checking runs before those checks, so root can use `run -check` to validate local files.

A cycle performs renewal if needed, pending-result upload, heartbeat, one task poll, validation/collection, and result upload/acknowledgment. `-once` does not drain the queue: it handles at most one newly delivered task and also succeeds when there is no task.

Continuous `run` logs and retries errors inside the cycle. `-once` and `renew` return the error directly. Credential/state loading failures occur before the loop and cause an exit. Processes opening agent state share an exclusive lock; stop the service before manual renewal.

## argus connection arguments

| Argument | Default | Meaning |
| --- | --- | --- |
| `-server` | `https://localhost:8443` | HTTPS origin, without a path prefix, query, fragment, or embedded credentials |
| `-ca` | None | Trusted CA file; required by network commands |
| `-token-file` | None | Private administrator token file; required by network commands |

`new-user` is a local credential-generation operation and needs no connection arguments. The client rejects redirects. Each HTTP request has a 40-second timeout. The subcommand `-timeout` defaults to `5m` and bounds the overall operation; `wait` polls every two seconds.

## argus subcommands

| Subcommand | Arguments | Minimum role | Output or result |
| --- | --- | --- | --- |
| `nodes` | Optional `-after ID` | ReadOnly | Node array, up to 200 per page |
| `tasks` | Optional `-after ID` | ReadOnly | Task array without results, up to 200 per page |
| `result` | `-task ID` | ReadOnly | Current `{task, result?}`; querying a failed task can still exit 0 |
| `wait` | `-task ID`, `-timeout 5m` | ReadOnly | Wait for `SUCCEEDED`, `FAILED`, or `UNKNOWN`; only success exits 0 |
| `create` | `-node ID`, `-type system.info`, `-ttl 300`, `-execution-timeout 10s`, `-resource ID` where required | Admin | Created task object |
| `enrollment-token` | `-out PATH`, `-ttl 300` | Admin | Write a token to a new mode-0600 file; print its location only |
| `disable` | `-node ID` | Admin | Set node status to `disabled`; return `{}` |
| `audit` | Optional `-after SEQUENCE` | ReadOnly | Audit event array, up to 200 per page |
| `health` | None | ReadOnly | `{"status":"ok"}` when the database is accessible |
| `new-user` | `-name NAME`, `-role ReadOnly`, `-out PATH` | Local operation | Save a token and print its account record; installation in the server account file is manual |

Admin includes all ReadOnly queries. Task TTL is 10–3600 seconds for first execution authorization; `-execution-timeout` is a whole number of milliseconds from `1ms` to `30s`, capped again by agent policy; enrollment-token TTL is 60–3600 seconds. Service and SSH tasks require `-resource`; parameterless tasks should omit it. There is no arbitrary JSON-parameter, command, script, or file-upload flag.

## Common calls

Adjust the connection details for your test deployment:

```sh
argus_admin() {
  /usr/local/libexec/argus-c2/argus \
    -server https://fleet.example.com:8443 \
    -ca /private/argus/ca.pem \
    -token-file /private/argus/admin.token "$@"
}
argus_admin nodes
argus_admin create -node NODE_ID -type service.status -resource journal -ttl 120
argus_admin result -task TASK_ID
argus_admin wait -task TASK_ID -timeout 2m
argus_admin audit -after 0
```

Replace `NODE_ID` and `TASK_ID` with returned IDs. Node and task IDs are random, not chronological. Use the final ID of a page for pagination; start a new listing to discover newly created records. Audit IDs increase monotonically, but retention can remove earlier records.

## Exit and output behavior

Successful commands exit 0. Parsing, file, network, permission, and service errors exit 1. `wait` also exits 1 after printing a failed or unknown outcome. Server and agent runtime logs are JSON on stderr; CLI errors are text on stderr, and query results are JSON on stdout.

The CLI displays HTTP status and recognized error codes, such as `server returned HTTP 409 (result_conflict)`, without echoing arbitrary response bodies. Use the [troubleshooting table](operations.md) to inspect the relevant node, task, and service. An `-out` file must not already exist. An enrollment token may already have been created remotely if saving it locally fails; retrying creates another token.
