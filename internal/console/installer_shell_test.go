package console

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Exercise the actual script with all destinations redirected into t.TempDir.
// System/account management and downloads are stand-ins; no service is installed,
// no real account is created and no root privileges or networking are needed.
func TestInstallerShellLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux shell fixture")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for isolated command stand-ins")
	}
	for _, scenario := range []string{"success", "checksum", "enrollment-failure", "existing-state"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			for _, dir := range []string{bin, root + "/run/systemd/system", root + "/var/tmp"} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			stub := []byte("#!/bin/sh\nif [ \"$1\" = enroll ]; then exit \"$ARGUS_TEST_ENROLL_EXIT\"; fi\n")
			artifact := filepath.Join(root, "download-agent")
			if err := os.WriteFile(artifact, stub, 0700); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(stub)
			s := &Server{config: Config{Origin: "https://console.example", FleetOrigin: "https://fleet.example"}, installer: &installer{artifacts: map[string]installArtifact{"amd64": {hash: hex.EncodeToString(hash[:])}}}}
			script := s.renderInstallation(installTicket{token: "SHELL_TEST_ONLY", expires: time.Now().Add(time.Hour).Unix()})
			script = strings.NewReplacer("/etc/", root+"/etc/", "/usr/local/", root+"/usr/local/", "/var/", root+"/var/", "/run/", root+"/run/").Replace(script)
			wrapper := "#!" + python + "\n" + `import os, sys, pathlib, shutil
root = pathlib.Path(os.environ['ARGUS_TEST_ROOT']).resolve()
tool, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
def safe(path):
    value = pathlib.Path(path).resolve()
    assert value.is_relative_to(root), 'fixture attempted a host write'
    return value
with open(root / 'calls', 'a') as log:
    log.write(tool + ' ' + ' '.join(args) + '\n')
if tool == 'id': print('0')
elif tool == 'uname': print('Linux' if args == ['-s'] else 'x86_64')
elif tool == 'getent': sys.exit(2)
elif tool == 'systemd-sysusers': pass
elif tool == 'systemctl': sys.exit(1 if args[0] == 'cat' else 0)
elif tool == 'curl':
    target = safe(args[args.index('--output')+1])
    shutil.copyfile(os.environ['ARGUS_TEST_ARTIFACT'], target)
    if os.environ['ARGUS_TEST_SCENARIO'] == 'checksum': target.write_bytes(b'corrupt')
elif tool == 'install':
    directory, mode, paths = False, 0o755, []
    while args:
        arg = args.pop(0)
        if arg == '-d': directory = True
        elif arg == '-m': mode = int(args.pop(0), 8)
        elif arg in ['-o', '-g']: args.pop(0)
        else: paths.append(safe(arg))
    if directory:
        for path in paths: path.mkdir(parents=True, exist_ok=True); path.chmod(mode)
    else:
        shutil.copyfile(paths[0], paths[1]); paths[1].chmod(mode)
elif tool == 'runuser':
    assert args[:3] == ['-u', 'argus-agent', '--']
    safe(args[3])
    os.execv(args[3], args[3:])
else: raise AssertionError('unexpected tool')
`
			for _, name := range []string{"id", "uname", "getent", "systemctl", "systemd-sysusers", "install", "runuser", "curl"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(wrapper), 0700); err != nil {
					t.Fatal(err)
				}
			}
			state := root + "/var/lib/argus-c2-agent"
			if scenario == "existing-state" {
				if err := os.MkdirAll(state, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(state+"/identity", []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			enrollExit := "0"
			if scenario == "enrollment-failure" {
				enrollExit = "1"
			}
			run := func() ([]byte, error) {
				cmd := exec.Command("sh")
				cmd.Stdin = strings.NewReader(script)
				cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "ARGUS_TEST_ROOT="+root, "ARGUS_TEST_ARTIFACT="+artifact, "ARGUS_TEST_SCENARIO="+scenario, "ARGUS_TEST_ENROLL_EXIT="+enrollExit)
				return cmd.CombinedOutput()
			}
			out, err := run()
			if (err == nil) != (scenario == "success") {
				t.Fatalf("unexpected result: %v: %s", err, out)
			}
			calls, err := os.ReadFile(root + "/calls")
			if err != nil {
				t.Fatal(err)
			}
			started := strings.Contains(string(calls), "systemctl enable --now")
			if started != (scenario == "success") {
				t.Fatal("service start before successful enrollment")
			}
			if _, err := os.Stat(state + "/enroll.token"); !os.IsNotExist(err) {
				t.Fatal("token file survived", err)
			}
			stages, err := filepath.Glob(root + "/var/tmp/argus-install.*")
			if err != nil || len(stages) != 0 {
				t.Fatal("temporary credentials survived", stages, err)
			}
			if scenario == "success" || scenario == "enrollment-failure" {
				before, err := os.ReadFile(root + "/etc/argus-c2/agent.json")
				if err != nil {
					t.Fatal(err)
				}
				out, err := run()
				if err == nil || !strings.Contains(string(out), "already exists") {
					t.Fatal("repeat installation did not stop", err, string(out))
				}
				after, _ := os.ReadFile(root + "/etc/argus-c2/agent.json")
				if string(before) != string(after) {
					t.Fatal("repeat changed configuration")
				}
			} else {
				if strings.Contains(string(calls), "install -") {
					t.Fatal("preflight failure wrote installation files")
				}
			}
		})
	}
}
