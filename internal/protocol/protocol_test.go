package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
)

func testTask() Task {
	return Task{Version: 1, RequestID: strings.Repeat("1", 32), AgentID: strings.Repeat("2", 32), EnrollmentEpoch: strings.Repeat("3", 32), CreatedAt: 2000000000, ExpiresAt: 2000000060, Type: SystemInfo, TaskVersion: 1, Params: json.RawMessage(`{}`), ActorID: "admin", PolicyDigest: strings.Repeat("a", 64)}
}
func TestTaskValidation(t *testing.T) {
	good := testTask()
	data, _ := json.Marshal(good)
	if _, err := DecodeTask(data); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Task){
		"unknown task":         func(t *Task) { t.Type = "shell" },
		"future service task":  func(t *Task) { t.Type = "service.restart" },
		"version":              func(t *Task) { t.Version = 2 },
		"task version":         func(t *Task) { t.TaskVersion = 2 },
		"request id":           func(t *Task) { t.RequestID = "arbitrary" },
		"uppercase ID":         func(t *Task) { t.AgentID = strings.Repeat("A", 32) },
		"epoch":                func(t *Task) { t.EnrollmentEpoch = "" },
		"policy":               func(t *Task) { t.PolicyDigest = "" },
		"actor":                func(t *Task) { t.ActorID = "../root" },
		"negative timestamp":   func(t *Task) { t.CreatedAt = -1 },
		"unordered timestamps": func(t *Task) { t.ExpiresAt = t.CreatedAt },
		"long lifetime":        func(t *Task) { t.ExpiresAt = t.CreatedAt + 301 },
		"extra params":         func(t *Task) { t.Params = json.RawMessage(`{"command":"x"}`) },
		"null params":          func(t *Task) { t.Params = json.RawMessage(`null`) },
		"array params":         func(t *Task) { t.Params = json.RawMessage(`[]`) },
		"oversized params":     func(t *Task) { t.Params = json.RawMessage("{" + strings.Repeat(" ", MaxParamsBytes) + "}") },
	} {
		t.Run(name, func(t *testing.T) {
			task := good
			mutate(&task)
			if task.Validate() == nil {
				t.Fatal("accepted invalid task")
			}
		})
	}
	for name, invalid := range map[string]string{
		"case":      strings.Replace(string(data), `"version"`, `"Version"`, 1),
		"duplicate": strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1),
		"fraction":  strings.Replace(string(data), `"created_at":2000000000`, `"created_at":2000000000.0`, 1),
		"exponent":  strings.Replace(string(data), `"created_at":2000000000`, `"created_at":2e9`, 1),
		"overflow":  strings.Replace(string(data), `"expires_at":2000000060`, `"expires_at":9223372036854775808`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTask([]byte(invalid)); err == nil {
				t.Fatal("accepted invalid wire data")
			}
		})
	}
}
func TestTaskPreflight(t *testing.T) {
	task := testTask()
	node := identity.Node{AgentID: task.AgentID, EnrollmentEpoch: task.EnrollmentEpoch}
	for _, seconds := range []int64{task.CreatedAt - 30, task.CreatedAt, task.ExpiresAt - 1} {
		if err := task.CheckTarget(node, task.PolicyDigest, time.Unix(seconds, 0)); err != nil {
			t.Fatal(err)
		}
	}
	for _, seconds := range []int64{task.CreatedAt - 31, task.ExpiresAt, task.ExpiresAt + 1} {
		if task.CheckTarget(node, task.PolicyDigest, time.Unix(seconds, 0)) == nil {
			t.Fatal("accepted expired/future request")
		}
	}
	if task.CheckTarget(identity.New(), task.PolicyDigest, time.Unix(task.CreatedAt, 0)) == nil {
		t.Fatal("accepted wrong target")
	}
	wrongEpoch := node
	wrongEpoch.EnrollmentEpoch = identity.RandomID()
	if task.CheckTarget(wrongEpoch, task.PolicyDigest, time.Unix(task.CreatedAt, 0)) == nil {
		t.Fatal("accepted old epoch")
	}
	if task.CheckTarget(node, strings.Repeat("b", 64), time.Unix(task.CreatedAt, 0)) == nil {
		t.Fatal("accepted changed policy")
	}
}
func FuzzDecodeTask(f *testing.F) {
	data, _ := json.Marshal(testTask())
	f.Add(data)
	for _, kind := range []TaskType{SSHAudit, ServiceStatus} {
		task := testTask()
		task.Type = kind
		task.Params = json.RawMessage(`{"profile_id":"host"}`)
		if kind == ServiceStatus {
			task.Params = json.RawMessage(`{"service_id":"ssh"}`)
		}
		b, _ := json.Marshal(task)
		f.Add(b)
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		task, err := DecodeTask(b)
		if err == nil {
			if err := task.Validate(); err != nil {
				t.Fatal(err)
			}
			if len(b) > MaxPayloadBytes {
				t.Fatal("size bound bypassed")
			}
		}
	})
}
