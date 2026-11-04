package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func seed() []byte {
	b, _ := json.Marshal(Task{ID: "task", NodeID: "node", Type: SystemInfo, Params: json.RawMessage(`{}`), Status: Accepted, CreatedAt: time.Now().Unix(), DispatchExpiresAt: time.Now().Add(time.Minute).Unix(), ExecutionTimeoutMS: 10000, ResultDueAt: time.Now().Add(2 * time.Minute).Unix()})
	return b
}
func TestStrictTaskAndParameterSchemas(t *testing.T) {
	b := seed()
	if _, e := DecodeTask(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{string(b) + "{}", strings.Replace(string(b), `"id":"task"`, `"id":"task","id":"other"`, 1), strings.Replace(string(b), `"parameters":{}`, `"parameters":{"command":"id"}`, 1), strings.Replace(string(b), `"system.info"`, `"shell"`, 1), strings.Replace(string(b), `"parameters":{}`, `"parameters":null`, 1), strings.Repeat(" ", MaxPayloadBytes) + string(b)} {
		if _, e := DecodeTask([]byte(bad)); e == nil {
			t.Fatalf("accepted malformed task %s", bad[:min(100, len(bad))])
		}
	}
	for _, params := range []string{`{}`, `{"service_id":"../x"}`, `{"service_id":"x","unit":"sshd.service"}`, `{"SERVICE_ID":"x"}`} {
		if e := ValidateParams(ServiceStatus, json.RawMessage(params)); e == nil {
			t.Fatal("accepted invalid service params", params)
		}
	}
}
func FuzzDecodeTask(f *testing.F) {
	f.Add(seed())
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, e := DecodeTask(b); e == nil {
			if e = v.Validate(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
func FuzzDecodeResult(f *testing.F) {
	f.Add([]byte(`{"task_id":"t","node_id":"n","status":"UNKNOWN","payload":{},"error":"interrupted","completed_at":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, e := DecodeResult(b); e == nil {
			if e = v.Validate(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
