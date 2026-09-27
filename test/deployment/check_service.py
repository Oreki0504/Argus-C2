"""CI-only checks executed inside each installed systemd unit's restrictions."""
import errno
import os
from pathlib import Path
import sys
import tempfile

role = sys.argv[1]
assert role in ("server", "probe")
assert os.getuid() != 0
assert set(os.getgroups()) <= {os.getgid()}, "unexpected supplementary authority"
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    assert int(status[name].strip(), 16) == 0, name


def denied_open(path, flags):
    try:
        fd = os.open(path, flags)
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), (path, error)
    else:
        os.close(fd)
        raise AssertionError("unexpected access: " + str(path))


config = Path("/etc/argus-c2") / role
for path in (config, Path("/usr/local/libexec/argus-c2"), Path("/etc/systemd/system")):
    current = path
    while current != current.parent:
        st = current.lstat()
        assert not current.is_symlink() and st.st_uid == 0 and st.st_mode & 0o022 == 0, str(current)
        current = current.parent
for path in (config / "ca.pem", Path("/usr/local/libexec/argus-c2") / ("server" if role == "server" else "agent"),
             Path("/etc/systemd/system") / ("argus-c2-" + role + ".service")):
    denied_open(path, os.O_WRONLY)
if role == "probe":
    for name in ("policy.json", "task-public.pem", "identity.json"):
        denied_open(config / name, os.O_WRONLY)
# The world-writable fixture distinguishes mount restrictions from Unix DAC.
denied_open("/var/lib/argus-c2-ci-writable/check", os.O_WRONLY | os.O_CREAT)
denied_open("/home/argus-c2-ci-readable/check", os.O_RDONLY)
other = "probe" if role == "server" else "server"
denied_open("/var/lib/argus-c2-" + other + "/ci-private", os.O_RDONLY)
assert not Path("/tmp/argus-c2-ci-host-marker").exists(), "host /tmp visible"
key = Path(os.environ["CREDENTIALS_DIRECTORY"]) / ("server-key" if role == "server" else "probe-key")
assert key.read_bytes(), "credential unavailable"
denied_open(key, os.O_WRONLY)
state = Path("/var/lib/argus-c2-" + role)
assert state.stat().st_uid == os.getuid() and state.stat().st_mode & 0o077 == 0
with tempfile.TemporaryFile(dir=state) as file:
    file.write(b"local state remains writable")
    file.flush()
    os.fsync(file.fileno())
print("Verified effective service restrictions:", role)
