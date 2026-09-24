package probe

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func TestSignedInspectionCannotExpandLocalResources(t *testing.T) {
	for _, kind := range []protocol.TaskType{protocol.SSHAudit, protocol.ServiceStatus} {
		for _, scenario := range []string{"v1", "disabled", "unmapped", "changed_policy", "path", "extra", "valid", "wrong_result"} {
			t.Run(string(kind)+"/"+scenario, func(t *testing.T) {
				f := setup(t)
				if scenario != "v1" {
					f.p.Version = 2
					f.p.AllowSSHAudit = scenario != "disabled"
					f.p.AllowServiceStatus = scenario != "disabled"
					f.p.SSHProfiles = []resources.SSHProfile{{ID: "approved", Files: []resources.SSHFile{{ID: "config", Kind: "sshd_config", BaseDir: "/etc/ssh", RelativePath: "sshd_config", MaxBytes: 1024}}}}
					f.p.Services = []resources.Service{{ID: "approved", Unit: "sshd.service"}}
				}
				f.save(t)
				task := f.task()
				task.Type = kind
				field := "profile_id"
				if kind == protocol.ServiceStatus {
					field = "service_id"
				}
				task.Params = json.RawMessage(`{"` + field + `":"approved"}`)
				want := ""
				switch scenario {
				case "v1", "disabled":
					want = "task_disabled"
				case "unmapped":
					task.Params = json.RawMessage(`{"` + field + `":"unmapped"}`)
					want = "resource_denied"
				case "changed_policy":
					f.p.Services[0].Unit = "changed.service"
					f.save(t)
					want = "policy_mismatch"
				case "path":
					task.Params = json.RawMessage(`{"` + field + `":"../../etc/shadow"}`)
				case "extra":
					task.Params = json.RawMessage(`{"` + field + `":"approved","unit":"evil.service"}`)
				case "wrong_result":
					want = "collector_failed"
				}
				f.e.execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
					f.calls.Add(1)
					id := "approved"
					if scenario == "wrong_result" {
						id = "another"
					}
					if kind == protocol.ServiceStatus {
						return json.Marshal(protocol.ServiceReport{ServiceID: id, ObservedAt: time.Now().Unix(), Code: "unsupported"})
					}
					return json.Marshal(protocol.SSHReport{ProfileID: id, ObservedAt: time.Now().Unix(), Coverage: "unavailable", Files: []protocol.SSHFileObservation{{ID: "config", Kind: "sshd_config", Status: "unsupported", Baseline: "unavailable", Keys: []protocol.KeyObservation{}, Directives: []protocol.DirectiveObservation{}, Findings: []string{}}}})
				}
				b, err := f.e.Process(t.Context(), f.envelope(task))
				if scenario == "path" || scenario == "extra" {
					if err == nil || f.calls.Load() != 0 {
						t.Fatal("signed arbitrary selector reached collector", err)
					}
					return
				}
				r := result(t, b, err)
				if string(r.ErrorCode) != want {
					t.Fatalf("got %s want %s", r.ErrorCode, want)
				}
				calls := int32(0)
				if scenario == "valid" || scenario == "wrong_result" {
					calls = 1
				}
				if f.calls.Load() != calls {
					t.Fatal("unexpected collector invocation")
				}
				if _, err := f.e.Process(t.Context(), f.envelope(task)); err != nil || f.calls.Load() != calls {
					t.Fatal("resource outcome not cached", err)
				}
			})
		}
	}
}
