package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func task(id string) protocol.Task {
	return protocol.Task{ID: id, NodeID: "node", Type: protocol.SystemInfo, Params: json.RawMessage(`{}`), Status: protocol.Accepted, CreatedAt: time.Now().Unix(), DispatchExpiresAt: time.Now().Add(time.Minute).Unix(), ExecutionTimeoutMS: 10000, ResultDueAt: time.Now().Add(2 * time.Minute).Unix()}
}
func goodPayload() json.RawMessage {
	return json.RawMessage(`{"available":false,"os":"linux","architecture":"amd64","hostname":"","kernel":"","boot_time":0}`)
}
func start(context.Context, string) error { return nil }
func TestConcurrentDeliveryAndRestartDeduplicate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	s, e := OpenState(dir, "node", true)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls.Add(1)
		return goodPayload(), nil
	}}
	job := task("same")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, e := engine.Process(t.Context(), job, start)
			if e != nil || r.Status != protocol.Succeeded {
				t.Errorf("%+v %v", r, e)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("collector ran %d times", calls.Load())
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenState(dir, "node", false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	engine.State = s
	if _, e = engine.Process(t.Context(), job, start); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate executed after restart")
	}
}

func TestTaskIDCannotBeRebound(t *testing.T) {
	s, err := OpenState(filepath.Join(t.TempDir(), "agent"), "node", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	calls := 0
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls++
		return goodPayload(), nil
	}}
	job := task("bound")
	if _, err = engine.Process(t.Context(), job, start); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*protocol.Task){
		"node":     func(v *protocol.Task) { v.NodeID = "other-node" },
		"type":     func(v *protocol.Task) { v.Type = protocol.SystemMetrics },
		"created":  func(v *protocol.Task) { v.CreatedAt-- },
		"dispatch": func(v *protocol.Task) { v.DispatchExpiresAt++ },
		"budget":   func(v *protocol.Task) { v.ExecutionTimeoutMS++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := job
			mutate(&changed)
			if err := changed.Validate(); err != nil {
				t.Fatal("fixture must remain valid", err)
			}
			if _, err := engine.Process(t.Context(), changed, start); err == nil {
				t.Fatal("task ID rebound")
			}
		})
	}
	observed := job
	observed.Status = protocol.Running
	observed.ResultDueAt++
	if _, err = engine.Process(t.Context(), observed, start); err != nil || calls != 1 {
		t.Fatal("mutable server observations broke deduplication", err, calls)
	}
	// Resource parameters must also remain bound even before collection starts.
	resource := task("resource")
	resource.Type = protocol.ServiceStatus
	resource.Params = json.RawMessage(`{"service_id":"first"}`)
	if _, err = s.prepare(t.Context(), resource); err != nil {
		t.Fatal(err)
	}
	resource.Params = json.RawMessage(`{"service_id":"second"}`)
	if _, err = s.prepare(t.Context(), resource); err == nil {
		t.Fatal("resource assignment rebound")
	}
	job.ID = "new-task"
	if _, err = engine.Process(t.Context(), job, start); err != nil || calls != 2 {
		t.Fatal("new task was blocked", err, calls)
	}
}
func TestInterruptedTasksBecomeUnknown(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	s, e := OpenState(dir, "node", true)
	if e != nil {
		t.Fatal(e)
	}
	original := task("interrupted")
	if _, e = s.prepare(t.Context(), original); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = OpenState(dir, "node", false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		t.Error("interrupted task re-executed")
		return nil, nil
	}}
	r, e := engine.Process(t.Context(), original, start)
	if e != nil || r.Status != protocol.Unknown {
		t.Fatal(r, e)
	}
	pending, e := s.Pending(t.Context())
	if e != nil || len(pending) != 1 {
		t.Fatal(pending, e)
	}
}
func TestPolicyExpiryIdentityTimeoutAndOutputLimits(t *testing.T) {
	for _, name := range []string{"policy", "expiry", "identity", "future", "timeout", "output"} {
		t.Run(name, func(t *testing.T) {
			s, e := OpenState(filepath.Join(t.TempDir(), "agent"), "node", true)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			p := policy.Default()
			job := task(name)
			calls := 0
			collect := func(ctx context.Context, _ protocol.Task, _ policy.Policy) (json.RawMessage, error) {
				calls++
				if name == "timeout" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				if name == "output" {
					return json.RawMessage(`{"secret":"unexpected schema"}`), nil
				}
				return goodPayload(), nil
			}
			switch name {
			case "policy":
				p.Allowed = []protocol.TaskType{}
			case "expiry":
				job.CreatedAt = time.Now().Add(-time.Minute).Unix()
				job.DispatchExpiresAt = time.Now().Unix()
				job.ResultDueAt = job.DispatchExpiresAt + protocol.ResultGraceSeconds
			case "identity":
				job.NodeID = "another-node"
			case "future":
				job.CreatedAt = time.Now().Add(time.Minute).Unix()
				job.DispatchExpiresAt = job.CreatedAt + 60
				job.ResultDueAt = job.DispatchExpiresAt + protocol.ResultGraceSeconds
			case "timeout":
				p.TimeoutSeconds = 1
			}
			r, e := (&Engine{State: s, Policy: p, Execute: collect}).Process(t.Context(), job, start)
			if name == "identity" {
				if e == nil {
					t.Fatal("cross-node task accepted")
				}
			} else if e != nil || r.Status != protocol.Failed {
				t.Fatal(r, e)
			}
			if name != "timeout" && name != "output" && calls != 0 {
				t.Fatal("unauthorized collector ran")
			}
		})
	}
}
func TestResultWriteFailureNeverRerunsCollector(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "agent"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	calls := 0
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls++
		_, e := s.db.Exec(`CREATE TRIGGER fail_result BEFORE UPDATE OF result ON executions BEGIN SELECT RAISE(FAIL,'injected disk failure'); END`)
		if e != nil {
			t.Fatal(e)
		}
		return goodPayload(), nil
	}}
	job := task("failure")
	if _, e = engine.Process(t.Context(), job, start); e == nil {
		t.Fatal("write failure hidden")
	}
	if _, e = s.db.Exec("DROP TRIGGER fail_result"); e != nil {
		t.Fatal(e)
	}
	r, e := engine.Process(t.Context(), job, start)
	if e != nil || r.Status != protocol.Unknown || calls != 1 {
		t.Fatal(r, e, calls)
	}
}
func TestMissingStateAndSecondWorkerRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	s, e := OpenState(dir, "node", true)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := OpenState(dir, "node", false); e == nil {
		other.Close()
		t.Fatal("second worker acquired state")
	}
	s.Close()
	if e = os.Remove(filepath.Join(dir, "probe.db")); e != nil {
		t.Fatal(e)
	}
	if state, e := OpenState(dir, "node", false); e == nil {
		state.Close()
		t.Fatal("lost replay state silently reset")
	}
}

func TestValidCollectorOutputStillObeysLocalSizeLimit(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "agent"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p := policy.Default()
	p.Allowed = append(p.Allowed, protocol.ProcessList)
	p.MaxResultBytes = 1024
	job := task("large-output")
	job.Type = protocol.ProcessList
	execute := func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		items := make([]protocol.Process, 100)
		for i := range items {
			items[i] = protocol.Process{PID: i + 1, Name: "process-name", State: "S", UID: 1000}
		}
		return json.Marshal(protocol.Processes{Available: true, Items: items})
	}
	r, e := (&Engine{State: s, Policy: p, Execute: execute}).Process(t.Context(), job, start)
	if e != nil || r.Status != protocol.Failed || r.Error != "result_too_large" {
		t.Fatal(r, e)
	}
}
