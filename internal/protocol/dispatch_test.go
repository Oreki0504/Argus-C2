package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func resultSeed() []byte {
	r := Result{RequestID: strings.Repeat("1", 32), AgentID: strings.Repeat("2", 32), Epoch: strings.Repeat("3", 32), Type: SystemInfo, StartedAt: 1, FinishedAt: 2, Status: Failed, Data: json.RawMessage(`{}`), ErrorCode: "deadline", PolicyDigest: strings.Repeat("a", 64)}
	b, _ := json.Marshal(r)
	return b
}
func TestStrictTerminalResult(t *testing.T) {
	seed := resultSeed()
	if _, err := DecodeResult(seed); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{`"status":"failed"`, `"status":"running"`}, {`"error_code":"deadline"`, `"error_code":"unknown"`}, {`"data":{}`, `"data":{"extra":true}`}, {`"truncated":false`, `"truncated":true`}, {`"finished_at":2`, `"finished_at":0`}, {`"epoch":`, `"epoch":null,"epoch":`}, {`"task_type":"system.info"`, `"task_type":"shell.exec"`}} {
		bad := bytes.Replace(seed, []byte(pair[0]), []byte(pair[1]), 1)
		if _, err := DecodeResult(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
func TestHeartbeatVersionsAreStrict(t *testing.T) {
	h := Heartbeat{Version: TaskHeartbeatVersion, AgentID: strings.Repeat("1", 32), EnrollmentEpoch: strings.Repeat("2", 32), SentAt: 100, Info: SystemInformation{OS: "test", Architecture: "test"}, Metrics: SystemMeasurements{Disks: []DiskStats{}, Networks: []NetworkStats{}}, PolicyDigest: strings.Repeat("a", 64), TaskState: "ready"}
	b, _ := json.Marshal(h)
	if _, err := DecodeHeartbeat(b); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{`"version":2`, `"version":1`}, {`"task_state":"ready"`, `"task_state":"unknown"`}, {`"task_state":"ready"`, `"task_state":null`}, {`"version":2`, `"version":2,"version":2`}} {
		if _, err := DecodeHeartbeat(bytes.Replace(b, []byte(pair[0]), []byte(pair[1]), 1)); err == nil {
			t.Fatal("invalid v2 heartbeat accepted")
		}
	}
}
func FuzzDecodeResult(f *testing.F) {
	f.Add(resultSeed())
	for _, kind := range []TaskType{SSHAudit, ServiceStatus} {
		b, _ := json.Marshal(inspectionResult(kind))
		f.Add(b)
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeResult(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeResult(encoded); err != nil {
			t.Fatal("accepted result failed roundtrip", err)
		}
	})
}
