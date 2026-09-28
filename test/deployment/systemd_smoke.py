"""Install and exercise services on a disposable GitHub-hosted Linux VM only.

Never run on a workstation or deployed host. Root setup belongs to this fixture;
all Argus application commands execute as dedicated non-root service accounts.
"""
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import traceback

if sys.argv[1:] != ["--disposable-ci"] or os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() != 0:
    sys.exit("Requires an explicitly selected disposable GitHub Actions VM and root fixture setup")
repo = Path(__file__).resolve().parents[2]
build = repo / ".cache/deployment-bin"
lib = Path("/usr/local/libexec/argus-c2")
etc = Path("/etc/argus-c2")
work = Path("/var/lib/argus-c2-ci")
states = {role: Path("/var/lib/argus-c2-" + role) for role in ("server", "probe")}
units = ["argus-c2-server.service", "argus-c2-probe.service"]
for path in (lib, etc, work, *states.values(), Path("/var/lib/argus-c2-ci-writable"), Path("/home/argus-c2-ci-readable")):
    assert not path.exists() and not path.is_symlink(), "fixture refuses existing path: " + str(path)
for unit in units:
    assert not Path("/etc/systemd/system", unit).exists()
for role in states:
    try:
        pwd.getpwnam("argus-" + role)
    except KeyError:
        pass
    else:
        raise AssertionError("fixture refuses existing service account")


def run(*args, user=None, data=None, ok=True):
    argv = [str(arg) for arg in args]
    if user:
        argv = ["runuser", "-u", "argus-" + user, "--"] + argv
    result = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=35)
    if ok and result.returncode:
        # No argv or input: tokens and passwords must not enter CI diagnostics.
        raise AssertionError("fixture command failed: " + result.stderr[:2000])
    return result


def put(source, destination, mode=0o644):
    destination = Path(destination)
    assert not destination.is_symlink()
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def local(action, *args, data=None):
    return run(lib / "localctl", "-state", states["server"], "-action", action, *args, user="server", data=data)


def cli(action, *args, data=None, ok=True):
    return run(lib / "cli", "-server", "https://127.0.0.1:8445", "-ca", etc / "server/ca.pem",
               "-session", states["server"] / "ci-session", "-action", action, *args, user="server", data=data, ok=ok)


def eventually(fn, message, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(2)
    raise AssertionError(message)


def state_value(query, args=()):
    db = sqlite3.connect("file:" + str(states["server"] / "argus.db") + "?mode=ro", uri=True)
    try:
        return db.execute(query, args).fetchone()
    finally:
        db.close()


def enroll():
    token = local("token", "-ttl", "120s").stdout
    out = states["probe"] / ("enrollment-" + secrets.token_hex(4))
    run(lib / "enroll", "-server", "https://127.0.0.1:8444", "-ca", etc / "probe/ca.pem", "-out", out,
        user="probe", data=token)
    for name in ("identity.json", "probe-cert.pem"):
        put(out / name, etc / "probe" / name)
    put(out / "probe-key.pem", etc / "probe/secrets/probe-key.pem", 0o600)
    # Remove only the disposable duplicate key after installing it. Public
    # enrollment evidence remains available in the fixture for diagnostics.
    (out / "probe-key.pem").unlink()
    run(lib / "probectl", "-action", "init", "-state", states["probe"] / "replay",
        "-identity", etc / "probe/identity.json", "-task-public-key", etc / "probe/task-public.pem", user="probe")
    return json.loads((etc / "probe/identity.json").read_text())["agent_id"]


def ready(node):
    return state_value("SELECT task_state FROM nodes WHERE agent_id=?", (node,)) == ("ready",)


def submit(node, kind, *args):
    task = json.loads(cli("submit", "-agent-id", node, "-type", kind, "-ttl-seconds", "120", *args).stdout)
    request = task["request_id"]
    def completed():
        row = state_value("SELECT state,result FROM tasks WHERE request_id=?", (request,))
        if row and row[0] not in ("queued", "dispatched"):
            assert row[0] == "succeeded", row[0]
            return json.loads(row[1])
    return eventually(completed, "task did not complete under systemd restrictions")


try:
    work.mkdir(mode=0o700)
    lib.mkdir(parents=True, mode=0o755)
    etc.mkdir(mode=0o755)
    for name in ("server", "agent", "localctl", "probectl", "enroll", "cli"):
        put(build / name, lib / name, 0o755)
    put(repo / "test/deployment/check_service.py", lib / "check-service.py")
    run(build / "devpki", "-enrollment", "-out", work / "pki")
    run(build / "devsign", "-out", work / "signing")
    for role, state in states.items():
        run("systemd-sysusers", repo / ("deploy/linux/argus-c2-" + role + ".sysusers.conf"))
        account = pwd.getpwnam("argus-" + role)
        assert account.pw_shell == "/usr/sbin/nologin"
        state.mkdir(mode=0o700)
        os.chown(state, account.pw_uid, account.pw_gid)
        (state / "ci-private").write_text("private fixture")
        (state / "ci-private").chmod(0o600)
        os.chown(state / "ci-private", account.pw_uid, account.pw_gid)
        config = etc / role
        config.mkdir(mode=0o755)
        (config / "secrets").mkdir(mode=0o700)
        put(work / "pki/ca.pem", config / "ca.pem")
        unit = "argus-c2-" + role + ".service"
        put(repo / "deploy/linux" / unit, Path("/etc/systemd/system") / unit)
        dropin = Path("/etc/systemd/system") / (unit + ".d")
        dropin.mkdir(mode=0o755)
        (dropin / "ci-check.conf").write_text("[Service]\nExecStartPre=/usr/bin/python3 /usr/local/libexec/argus-c2/check-service.py " + role + "\n")
    for name in ("server-cert.pem", "issuer-cert.pem"):
        put(work / "pki" / name, etc / "server" / name)
    for name in ("server-key.pem", "issuer-key.pem"):
        put(work / "pki" / name, etc / "server/secrets" / name, 0o600)
    put(work / "signing/task-private.pem", etc / "server/secrets/task-private.pem", 0o600)
    put(work / "signing/task-public.pem", etc / "probe/task-public.pem")
    put(repo / "deploy/linux/enrollment.conf.example", "/etc/systemd/system/argus-c2-server.service.d/enrollment.conf")
    policy = json.loads((repo / "examples/task-policy-v2.json").read_text())
    policy["telemetry"]["sample_milliseconds"] = 100
    policy["allow_service_status"] = True
    policy["services"] = [{"id": "journal", "unit": "systemd-journald.service"}]
    (etc / "fixtures").mkdir(mode=0o755)
    (etc / "fixtures/sshd_config").write_text("PermitRootLogin no\nPasswordAuthentication no\n")
    policy["allow_ssh_audit"] = True
    policy["ssh_profiles"] = [{"id": "fixture", "files": [{
        "id": "config", "kind": "sshd_config", "base_dir": "/etc/argus-c2/fixtures",
        "relative_path": "sshd_config", "owner_uid": 0, "owner_gid": 0,
        "max_bytes": 1024, "baseline_sha256": ""
    }]}]
    (etc / "probe/policy.json").write_text(json.dumps(policy))
    # Accessible fixtures distinguish systemd isolation from Unix DAC.
    for path in (Path("/var/lib/argus-c2-ci-writable"), Path("/home/argus-c2-ci-readable")):
        path.mkdir(mode=0o777)
        path.chmod(0o777)
    Path("/home/argus-c2-ci-readable/check").write_text("readable outside ProtectHome")
    Path("/home/argus-c2-ci-readable/check").chmod(0o644)
    Path("/tmp/argus-c2-ci-host-marker").write_text("host tmp")
    password = secrets.token_urlsafe(24)
    local("user-add", "-username", "operator", "-role", "Admin", data=password + "\n")
    run("systemd-analyze", "verify", *["/etc/systemd/system/" + unit for unit in units])
    run("systemctl", "daemon-reload")
    run("systemctl", "start", units[0])
    # Type=exec confirms exec, not readiness. Wait for the socket before login.
    def listening():
        try:
            with socket.create_connection(("127.0.0.1", 8445), timeout=1):
                return True
        except OSError:
            return False
    eventually(listening, "server did not listen")
    cli("login", "-username", "operator", data=password + "\n")
    node = enroll()
    run("systemctl", "start", units[1])
    eventually(lambda: ready(node), "probe did not advertise readiness")
    assert submit(node, "system.info")["data"]["available"], "system information unavailable"
    assert submit(node, "system.metrics")["data"]["memory"]["available"], "memory metrics unavailable"
    service = submit(node, "service.status", "-service-id", "journal")["data"]
    assert service["load_state"] == "loaded", service
    observation = submit(node, "ssh.audit", "-profile-id", "fixture")["data"]["files"][0]
    assert observation["status"] == "ok", observation
    for role in states:
        restrict_suid = run("systemctl", "show", "--property=RestrictSUIDSGID", "--value", "argus-c2-" + role).stdout.strip()
        assert restrict_suid == ("yes" if role == "server" else "no"), (role, "RestrictSUIDSGID", restrict_suid)
        group = run("systemctl", "show", "--property=ControlGroup", "--value", "argus-c2-" + role).stdout.strip()
        cg = Path("/sys/fs/cgroup") / group.lstrip("/")
        assert (cg / "memory.max").read_text().strip() == str((512 if role == "server" else 192) * 1024 * 1024), (role, "memory.max", (cg / "memory.max").read_text())
        assert (cg / "pids.max").read_text().strip() == "128", (role, "pids.max", (cg / "pids.max").read_text())
        assert (cg / "memory.swap.max").read_text().strip() == "0", (role, "memory.swap.max", (cg / "memory.swap.max").read_text())
        quota, period = map(int, (cg / "cpu.max").read_text().split())
        assert quota / period == (1 if role == "server" else 0.5), (role, "cpu.max", quota, period)
    print("PASS: effective isolation, credentials, cgroups, HTTPS, mTLS, metrics, systemd query", flush=True)
    # Cold backup: stop every database writer; copy the entire directory.
    run("systemctl", "stop", *units)
    snapshot = work / "server-backup"
    shutil.copytree(states["server"], snapshot)
    local("sessions-revoke-all")
    # Restore under maintenance; preserve the replaced state as evidence.
    states["server"].rename(work / "server-before-restore")
    shutil.copytree(snapshot, states["server"])
    account = pwd.getpwnam("argus-server")
    for path in (states["server"], *states["server"].rglob("*")):
        os.chown(path, account.pw_uid, account.pw_gid)
    local("restore-quarantine")
    run("systemctl", "start", units[0])
    eventually(listening, "restored server did not listen")
    assert cli("me", ok=False).returncode != 0, "restored session survived local revocation"
    cli("forget")
    cli("login", "-username", "operator", data=password + "\n")
    assert state_value("SELECT enabled FROM nodes WHERE agent_id=?", (node,)) == (0,)
    # Missing replay state fails startup; no empty replacement may be created.
    run("systemctl", "stop", units[1])
    (states["probe"] / "replay").rename(work / "probe-replay-evidence")
    assert run("systemctl", "start", units[1], ok=False).returncode != 0
    run("systemctl", "stop", units[1])
    assert not (states["probe"] / "replay").exists()
    replacement = enroll()
    assert replacement != node
    # stop already cancelled the failed unit's pending restart. systemd may
    # garbage-collect it before reenrollment completes; start loads it again.
    run("systemctl", "start", units[1])
    eventually(lambda: ready(replacement), "fresh identity did not become ready")
    submit(replacement, "system.info")
    assert state_value("SELECT enabled FROM nodes WHERE agent_id=?", (node,)) == (0,)
    # Enrollment is temporary; close it without weakening management or mTLS.
    Path("/etc/systemd/system/argus-c2-server.service.d/enrollment.conf").unlink()
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", units[0])
    eventually(listening, "normal server did not restart")
    cli("me")
    with socket.socket() as connection:
        assert connection.connect_ex(("127.0.0.1", 8444)) != 0
    print("PASS: cold restore, session revocation, lost replay state, disable and fresh enrollment", flush=True)
except Exception:
    message = traceback.format_exc().replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error title=Deployment exercise::" + message, flush=True)
    for unit in units:
        log = run("journalctl", "-u", unit, "--no-pager", "-n", "25", ok=False).stdout
        log = log.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print("::error title=" + unit + "::" + log, flush=True)
    raise
finally:
    for unit in units:
        result = run("journalctl", "-u", unit, "--no-pager", "-n", "60", ok=False)
        print(result.stdout)
    run("systemctl", "stop", *units, ok=False)
