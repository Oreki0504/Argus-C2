package protocol

import (
	"encoding/json"
	"testing"
)

func TestResultSemanticIdentity(t *testing.T) {
	task := Task{ID: "t", NodeID: "n", Type: SystemInfo, Params: json.RawMessage(`{}`)}
	base := Result{TaskID: "t", NodeID: "n", Status: Succeeded, CompletedAt: 10, Payload: json.RawMessage(`{"available":false,"os":"linux","architecture":"amd64","hostname":"","kernel":"","boot_time":0}`)}
	reordered := base
	reordered.Payload = json.RawMessage(`{ "kernel":"", "hostname":"", "architecture":"amd64", "boot_time":0, "os":"linux", "available":false }`)
	if ok, e := EquivalentResults(task, base, reordered); e != nil || !ok {
		t.Fatal(ok, e)
	}
	changed := base
	changed.CompletedAt++
	if ok, e := EquivalentResults(task, base, changed); e != nil || ok {
		t.Fatal("timestamp change accepted", ok, e)
	}
	bad := base
	bad.Payload = json.RawMessage(`{"available":false,"available":true}`)
	if _, e := EquivalentResults(task, base, bad); e == nil {
		t.Fatal("malformed report compared")
	}
	failure := NewResult(task, Failed, "denied")
	other := failure
	other.Payload = json.RawMessage("{ \n }")
	if ok, e := EquivalentResults(task, failure, other); e != nil || !ok {
		t.Fatal("empty object whitespace", ok, e)
	}
	other.Error = "different"
	if ok, e := EquivalentResults(task, failure, other); e != nil || ok {
		t.Fatal("error change accepted", ok, e)
	}
}

func TestTypedEqualityPreservesCountersAndArrayOrder(t *testing.T) {
	job := Task{ID: "t", NodeID: "n", Type: SystemMetrics, Params: json.RawMessage(`{}`)}
	metrics := SystemMeasurements{CPU: CPUStats{Available: true, BusyPercent: 1, WindowMS: 100}, Memory: MemoryStats{Available: true, TotalBytes: 9007199254740993}, Disks: []DiskStats{}, Networks: []NetworkStats{}}
	b, _ := json.Marshal(metrics)
	a := Result{TaskID: "t", NodeID: "n", Status: Succeeded, CompletedAt: 10, Payload: b}
	metrics.Memory.TotalBytes--
	b, _ = json.Marshal(metrics)
	other := a
	other.Payload = b
	if ok, e := EquivalentResults(job, a, other); e != nil || ok {
		t.Fatal("uint64 precision lost", ok, e)
	}
	other = a
	other.Payload = json.RawMessage(`{"cpu":{"window_ms":100,"busy_percent":1.0,"available":true},"memory":{"available":true,"total_bytes":9007199254740993,"available_bytes":0},"disks":[],"networks":[]}`)
	if ok, e := EquivalentResults(job, a, other); e != nil || !ok {
		t.Fatal("equivalent typed float", ok, e)
	}
	job.Type = ProcessList
	a.Payload = json.RawMessage(`{"available":true,"truncated":false,"items":[{"pid":1,"name":"one","state":"S","uid":0},{"pid":2,"name":"two","state":"S","uid":0}]}`)
	other = a
	other.Payload = json.RawMessage(`{"available":true,"truncated":false,"items":[{"pid":2,"name":"two","state":"S","uid":0},{"pid":1,"name":"one","state":"S","uid":0}]}`)
	if ok, e := EquivalentResults(job, a, other); e != nil || ok {
		t.Fatal("array order erased", ok, e)
	}
}
