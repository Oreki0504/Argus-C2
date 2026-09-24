package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func resourcePolicy(t *testing.T) Policy {
	t.Helper()
	b, err := os.ReadFile("../../examples/task-policy-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	p.SSHProfiles = []resources.SSHProfile{{ID: "host", Files: []resources.SSHFile{{ID: "config", Kind: "sshd_config", BaseDir: "/etc/ssh", RelativePath: "sshd_config", MaxBytes: 65536}}}}
	p.Services = []resources.Service{{ID: "ssh", Unit: "sshd.service"}}
	return p
}
func TestV1WireAndDigestRemainUnchanged(t *testing.T) {
	const legacy = `{"version":1,"paused":false,"allow_system_info":true,"allow_system_metrics":true,"poll_seconds":5,"timeout_seconds":5,"max_per_minute":30,"burst":5,"max_result_bytes":16384,"pending_bytes":33554432,"telemetry":{"interval_seconds":30,"sample_milliseconds":1000,"disk_paths":["/"],"network_interfaces":["lo"]}}`
	p, err := Decode([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	digest, err := p.Digest()
	if err != nil || string(b) != legacy || digest != audit.Digest([]byte("argus-c2/policy/v1\x00"+legacy)) {
		t.Fatal("v1 authority changed", err)
	}
	if p.Allows(protocol.SSHAudit) || p.Allows(protocol.ServiceStatus) {
		t.Fatal("legacy authority widened")
	}
}
func TestV2ResourcesAreExplicitAndDigestBound(t *testing.T) {
	p := resourcePolicy(t)
	p.SSHProfiles = []resources.SSHProfile{}
	p.Services = []resources.Service{}
	b, _ := json.Marshal(p)
	round, err := Decode(b)
	if err != nil || round.AllowSSHAudit || round.AllowServiceStatus || round.SSHProfiles == nil || round.Services == nil {
		t.Fatal("empty opt-in roundtrip", err)
	}
	p = resourcePolicy(t)
	original, _ := json.Marshal(p)
	digest, _ := p.Digest()
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.AllowSSHAudit = true }, func(p *Policy) { p.AllowServiceStatus = true },
		func(p *Policy) { p.Services[0].ID = "other" }, func(p *Policy) { p.Services[0].Unit = "other.service" },
		func(p *Policy) { p.SSHProfiles[0].ID = "other" }, func(p *Policy) { p.SSHProfiles[0].Files[0].ID = "other" },
		func(p *Policy) { p.SSHProfiles[0].Files[0].BaseDir = "/srv/ssh" }, func(p *Policy) { p.SSHProfiles[0].Files[0].RelativePath = "sshd_config.d/extra.conf" },
		func(p *Policy) { p.SSHProfiles[0].Files[0].OwnerUID = 1001 }, func(p *Policy) { p.SSHProfiles[0].Files[0].OwnerGID = 1001 },
		func(p *Policy) { p.SSHProfiles[0].Files[0].MaxBytes = 1024 }, func(p *Policy) { p.SSHProfiles[0].Files[0].BaselineSHA256 = strings.Repeat("a", 64) },
	} {
		changed, _ := Decode(original)
		mutate(&changed)
		got, err := changed.Digest()
		if err != nil || got == digest {
			t.Fatal("resource authority omitted from digest", err)
		}
	}
	for _, pair := range [][2]string{
		{`"allow_ssh_audit":false`, `"allow_ssh_audit":null`}, {`"services":[`, `"services":null,"services":[`},
		{`"owner_uid":0`, `"owner_uid":0,"path":"/etc/shadow"`}, {`"relative_path":"sshd_config"`, `"relative_path":"../sshd_config"`},
		{`"relative_path":"sshd_config"`, `"relative_path":"id_ed25519"`}, {`"unit":"sshd.service"`, `"unit":"*.service"`},
		{`"files":[`, `"files":null,"files":[`}, {`"version":2`, `"version":1`},
	} {
		bad := bytes.Replace(original, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(bad, original) {
			t.Fatal("bad test mutation", pair)
		}
		if _, err := Decode(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	p.SSHProfiles = append(p.SSHProfiles, p.SSHProfiles[0])
	if p.Validate() == nil {
		t.Fatal("duplicate profile accepted")
	}
}
