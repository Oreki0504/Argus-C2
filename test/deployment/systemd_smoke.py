#!/usr/bin/env python3
"""Install real units only on a disposable GitHub Actions Linux VM."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time
import tempfile


def run(*args, parse=False):
    result = subprocess.run(list(map(str, args)), check=True, text=True,
                            capture_output=True, timeout=60)
    return json.loads(result.stdout) if parse else result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disposable-ci", action="store_true", required=True)
    parser.add_argument("--bin", type=Path, required=True)
    args = parser.parse_args()
    if not args.disposable_ci or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("This fixture requires root on an explicitly disposable GitHub Actions VM")
    if Path("/etc/argus-c2").exists():
        raise SystemExit("Refusing to touch an existing Argus installation")
    binaries = args.bin.resolve()
    # The state test is built by CI and runs as the checkout owner, not root.
    test_binary = binaries / "agent-state.test"
    owner = pwd.getpwuid(test_binary.stat().st_uid)
    if owner.pw_uid == 0:
        raise SystemExit("Filesystem pressure test must run as a non-root checkout owner")
    with tempfile.TemporaryDirectory(prefix="argus-full-") as temporary:
        mount = Path(temporary)
        run("mount", "-t", "tmpfs", "-o", "size=16m,mode=0700", "argus-full-test", mount)
        try:
            os.chown(mount, owner.pw_uid, owner.pw_gid)
            print(run("runuser", "-u", owner.pw_name, "--", "env",
                      f"ARGUS_ENOSPC_DIR={mount}", test_binary,
                      "-test.run=^TestFilesystemFullRecovery$", "-test.v"))
        finally:
            run("umount", mount)
    root = Path("/etc/argus-c2")
    server = root / "server"
    active = Path("/var/lib/argus-c2-server")
    state = Path("/var/lib/argus-c2-agent")
    run("sh", "deploy/linux/install.sh", binaries)
    run(binaries / "server", "init", "-dir", server, "-hosts", "localhost,127.0.0.1")
    shutil.copy2(server / "state/argus.db", active / "argus.db")
    account = pwd.getpwnam("argus-server")
    os.chown(active / "argus.db", account.pw_uid, account.pw_gid)
    server.chmod(0o755)
    for name in ["ca.pem", "server.pem"]:
        (server / name).chmod(0o644)
    config = {"listen": "127.0.0.1:8443", "state_dir": str(active),
              "certificate": str(server / "server.pem"), "ca": str(server / "ca.pem"),
              "private_key": "/run/credentials/argus-c2-server.service/server-key",
              "issuer_key": "/run/credentials/argus-c2-server.service/issuer-key",
              "admins": "/run/credentials/argus-c2-server.service/admins"}
    (root / "server.json").write_text(json.dumps(config))
    shutil.copy2(server / "ca.pem", root / "ca.pem")
    policy = json.loads(Path("examples/policy.json").read_text())
    policy["allowed"] += ["service.status", "ssh.audit", "network.listeners", "process.list"]
    policy["poll_seconds"] = 5
    policy["telemetry"]["sample_milliseconds"] = 100
    policy["services"] = [{"id": "journal", "unit": "systemd-journald.service"}]
    ssh_dir = root / "test-ssh"
    ssh_dir.mkdir(mode=0o755)
    (ssh_dir / "sshd_config").write_text("PermitRootLogin no\nPasswordAuthentication no\n")
    policy["ssh_profiles"] = [{"id": "host", "files": [{"id": "config", "kind": "sshd_config",
        "base_dir": str(ssh_dir), "relative_path": "sshd_config", "owner_uid": 0, "owner_gid": 0,
        "max_bytes": 4096, "baseline_sha256": ""}]}]
    (root / "policy.json").write_text(json.dumps(policy))
    (root / "agent.json").write_text(json.dumps({"server": "https://localhost:8443",
        "ca": str(root / "ca.pem"), "state_dir": str(state), "policy": str(root / "policy.json")}))
    admin = [binaries / "argus", "-server", "https://localhost:8443", "-ca", server / "ca.pem",
             "-token-file", server / "admin.token"]
    def cli(*argv):
        return run(*admin, *argv, parse=True)
    units = ["argus-c2-server", "argus-c2-agent"]
    try:
        run("systemctl", "start", units[0])
        for _ in range(100):
            try:
                cli("health")
                break
            except subprocess.CalledProcessError:
                time.sleep(0.1)
        else:
            raise RuntimeError("server health timeout")
        token = state / "enroll.token"
        run(*admin, "enrollment-token", "-out", token)
        user = pwd.getpwnam("argus-agent")
        os.chown(token, user.pw_uid, user.pw_gid)
        run("runuser", "-u", "argus-agent", "--", "/usr/local/libexec/argus-c2/agent", "enroll", "-config",
            root / "agent.json", "-token-file", token)
        token.unlink()
        run("systemctl", "start", units[1])
        node = cli("nodes")[0]
        for kind in policy["allowed"]:
            options = ["create", "-node", node["id"], "-type", kind]
            if kind == "service.status":
                options += ["-resource", "journal"]
            if kind == "ssh.audit":
                options += ["-resource", "host"]
            job = cli(*options)
            result = cli("wait", "-task", job["id"], "-timeout", "40s")
            assert result["task"]["status"] == "SUCCEEDED", result
            if kind == "service.status":
                assert result["result"]["payload"]["available"], result
            if kind == "ssh.audit":
                assert result["result"]["payload"]["coverage"] == "complete", result
        for unit in units:
            props = dict(line.split("=", 1) for line in run("systemctl", "show", unit,
                         "-p", "User", "-p", "NoNewPrivileges", "-p", "ProtectSystem",
                         "-p", "MemoryMax", "-p", "MainPID").splitlines())
            assert props["User"] in ["argus-server", "argus-agent"]
            assert props["NoNewPrivileges"] == "yes" and props["ProtectSystem"] == "strict"
            assert int(props["MemoryMax"]) <= 256 * 1024 * 1024 and int(props["MainPID"]) > 0
        run("systemctl", "restart", *units)
        for _ in range(100):
            try:
                cli("health")
                break
            except subprocess.CalledProcessError:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not become ready after restart")
        assert cli("result", "-task", job["id"])["task"]["status"] == "SUCCEEDED"
        print("Native systemd: six collectors, dedicated users, isolation, limits and restart passed")
    except Exception:
        for unit in units:
            print(run("journalctl", "-u", unit, "--no-pager", "-n", "80"))
        raise
    finally:
        subprocess.run(["systemctl", "stop", *units], check=False, timeout=60)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        # Captured child output is otherwise omitted from Python's traceback.
        # These commands only operate on this disposable test installation.
        details = [str(error)]
        for output in (error.stdout, error.stderr):
            if output:
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                print(output, file=sys.stderr)
                details.append(output)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            message = "\n".join(details)[-4000:]
            message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=Deployment subprocess failed::{message}", flush=True)
        raise
