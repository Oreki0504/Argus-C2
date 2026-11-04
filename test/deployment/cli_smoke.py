#!/usr/bin/env python3
"""Unprivileged, disposable, five-agent acceptance using the three real binaries."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", type=Path, required=True)
    args = parser.parse_args()
    binaries = args.bin.resolve()
    if os.geteuid() == 0:
        raise SystemExit("Run this local test as a non-root user")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="argus-cli-") as temporary:
        root = Path(temporary)
        server_dir = root / "server"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"https://127.0.0.1:{port}"
        def command(binary, *arguments, json_result=False, check=True):
            result = subprocess.run([str(binaries / binary), *map(str, arguments)],
                                    text=True, capture_output=True, timeout=45)
            if check and result.returncode:
                raise RuntimeError(f"{binary} failed: {result.stderr}")
            return json.loads(result.stdout) if json_result else result
        command("server", "init", "-dir", server_dir, "-hosts", "localhost,127.0.0.1",
                "-listen", f"127.0.0.1:{port}")
        admin = ["-server", origin, "-ca", server_dir / "ca.pem",
                 "-token-file", server_dir / "admin.token"]
        def cli(*arguments, **kwargs):
            return command("argus", *admin, *arguments, **kwargs)
        log = (root / "server.log").open("w+")
        process = None
        def start_server():
            nonlocal process
            process = subprocess.Popen([str(binaries / "server"), "run", "-config",
                                        str(server_dir / "server.json")], stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError("server exited: " + log.read())
                if cli("health", check=False).returncode == 0:
                    return
                time.sleep(0.05)
            raise RuntimeError("server readiness timeout")
        def stop_server():
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        try:
            start_server()
            policy = {"allowed": ["system.info", "system.metrics", "service.status",
                                  "network.listeners", "process.list"],
                      "poll_seconds": 5, "timeout_seconds": 5, "max_result_bytes": 65536,
                      "telemetry": {"sample_milliseconds": 100, "disk_paths": ["/"],
                                    "network_interfaces": []},
                      "services": [{"id": "journal", "unit": "systemd-journald.service"}],
                      "ssh_profiles": []}
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy))
            agents = []
            latencies = []
            for index in range(5):
                token = root / f"enroll-{index}.token"
                cli("enrollment-token", "-out", token)
                config = root / f"agent-{index}.json"
                config.write_text(json.dumps({"server": origin, "ca": str(server_dir / "ca.pem"),
                                              "state_dir": str(root / f"agent-{index}"),
                                              "policy": str(policy_path)}))
                command("agent", "enroll", "-config", config, "-token-file", token)
                token.unlink()
                command("agent", "run", "-config", config, "-once")
                agents.append(config)
            nodes = cli("nodes", json_result=True)
            assert len(nodes) == 5 and len({n["certificate_fingerprint"] for n in nodes}) == 5
            assert all(n["protocol_version"] == 1 and n["agent_version"].startswith("development") for n in nodes)
            # Every real agent polls, so ID ordering need not match enrollment ordering.
            jobs = []
            for node in nodes:
                for kind in ["system.info", "system.metrics", "service.status"]:
                    options = ["create", "-node", node["id"], "-type", kind]
                    if kind == "service.status":
                        options += ["-resource", "journal"]
                    jobs.append(cli(*options, json_result=True))
            before = time.monotonic()
            for _ in range(3):
                for config in agents:
                    command("agent", "run", "-config", config, "-once")
            for job in jobs:
                result = cli("result", "-task", job["id"], json_result=True)
                assert result["task"]["status"] == "SUCCEEDED", result
                latencies.append(time.monotonic() - before)
            stop_server()
            start_server()
            for job in jobs:
                assert cli("result", "-task", job["id"], json_result=True)["task"]["status"] == "SUCCEEDED"
            for config in agents:
                command("agent", "run", "-config", config, "-once")
            backup = root / "fleet-backup.db"
            command("server", "backup", "-config", server_dir / "server.json", "-out", backup)
            assert backup.stat().st_size > 0 and backup.stat().st_mode & 0o077 == 0
            storage = command("server", "storage", "-config", server_dir / "server.json", json_result=True)
            assert storage["database_bytes"] > 0 and storage["filesystem_available"]
            records = command("agent", "results", "-config", agents[0], json_result=True)
            assert records and all(r["delivery"] == "acknowledged" for r in records)
            local_task = records[0]["task_id"]
            export = root / "export.json"
            command("agent", "result-export", "-config", agents[0], "-task", local_task, "-out", export)
            assert json.loads(export.read_text())["task_id"] == local_task and export.stat().st_mode & 0o077 == 0
            assert command("agent", "result-discard", "-config", agents[0], "-task", local_task,
                           "-confirm-task", "wrong-task", check=False).returncode != 0
            command("agent", "result-discard", "-config", agents[0], "-task", local_task,
                    "-confirm-task", local_task)
            records = command("agent", "results", "-config", agents[0], json_result=True)
            assert next(r for r in records if r["task_id"] == local_task)["delivery"] == "discarded"
            command("agent", "run", "-config", agents[0], "-once")
            assert cli("result", "-task", local_task, json_result=True)["task"]["status"] == "SUCCEEDED"
            local_storage = command("agent", "storage", "-config", agents[0], json_result=True)
            assert local_storage["results"]["discarded_count"] == 1
            # Existing account files load only at startup; rotation/revocation
            # are exercised through the actual running server.
            observer = root / "observer.token"
            record = command("argus", "new-user", "-name", "observer", "-role", "ReadOnly",
                             "-out", observer, json_result=True)
            accounts = json.loads((server_dir / "admins.json").read_text())
            accounts["users"].append(record)
            (server_dir / "admins.json").write_text(json.dumps(accounts))
            def observer_cli(*arguments, check=True):
                return command("argus", "-server", origin, "-ca", server_dir / "ca.pem",
                               "-token-file", observer, *arguments, check=check)
            assert observer_cli("health", check=False).returncode != 0
            stop_server()
            start_server()
            observer_cli("health")
            assert observer_cli("create", "-node", nodes[0]["id"], check=False).returncode != 0
            accounts["users"].pop()
            (server_dir / "admins.json").write_text(json.dumps(accounts))
            observer_cli("health")
            stop_server()
            start_server()
            assert observer_cli("health", check=False).returncode != 0
            log.flush()
            log.seek(0)
            logs = log.read()
            assert observer.read_text().strip() not in logs and (server_dir / "admin.token").read_text().strip() not in logs
            print(json.dumps({"nodes": 5, "p0_tasks_succeeded": len(jobs),
                              "server_restart": "passed", "agent_restart": "passed", "backup": "passed",
                              "local_maintenance": "passed", "account_revocation": "passed", "storage": "passed",
                              "batch_submit_to_inspection_seconds": round(max(latencies), 3),
                              "total_seconds": round(time.monotonic() - started, 3)}, indent=2))
        finally:
            stop_server()
            log.close()


if __name__ == "__main__":
    main()
