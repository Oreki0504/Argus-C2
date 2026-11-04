package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestRunningPersistenceFailureBlocksExecution(t *testing.T) {
	for _, blockUnknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "running_only", true: "all_updates"}[blockUnknown], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "agent")
			s, e := OpenState(dir, "node", true)
			if e != nil {
				t.Fatal(e)
			}
			defer func() { s.Close() }()
			when := "WHEN NEW.status='RUNNING'"
			if blockUnknown {
				when = ""
			}
			if _, e = s.db.Exec("CREATE TRIGGER fail_running BEFORE UPDATE ON executions " + when + " BEGIN SELECT RAISE(FAIL,'injected write failure'); END"); e != nil {
				t.Fatal(e)
			}
			calls, authorizations := 0, 0
			engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
				calls++
				return goodPayload(), nil
			}}
			grant := func(context.Context, string) error { authorizations++; return nil }
			job := task("running-failed")
			if _, e = engine.Process(t.Context(), job, grant); e == nil {
				t.Fatal("write failure hidden")
			}
			if calls != 0 || authorizations != 1 {
				t.Fatal(calls, authorizations)
			}
			if _, e = engine.Process(t.Context(), job, grant); blockUnknown && e == nil {
				t.Fatal("storage failure bypassed")
			}
			if calls != 0 || authorizations != 1 {
				t.Fatal("failed RUNNING retried", calls, authorizations)
			}
			if blockUnknown {
				if _, e = engine.Process(t.Context(), task("new-job"), grant); e == nil {
					t.Fatal("new task bypassed storage barrier")
				}
			}
			if _, e = s.db.Exec("DROP TRIGGER fail_running"); e != nil {
				t.Fatal(e)
			}
			r, e := engine.Process(t.Context(), job, grant)
			if e != nil || r.Status != protocol.Unknown || calls != 0 || authorizations != 1 {
				t.Fatal(r, e, calls, authorizations)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s, e = OpenState(dir, "node", false)
			if e != nil {
				t.Fatal(e)
			}
			engine.State = s
			r, e = engine.Process(t.Context(), job, grant)
			if e != nil || r.Status != protocol.Unknown || calls != 0 {
				t.Fatal(r, e, calls)
			}
		})
	}
}

func TestExecutionBudgetStartsAfterGrant(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "agent"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	job := task("budget")
	job.ExecutionTimeoutMS = 150
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(ctx context.Context, _ protocol.Task, _ policy.Policy) (json.RawMessage, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < 100*time.Millisecond {
			t.Error("network consumed collection budget")
		}
		return goodPayload(), nil
	}}
	r, e := engine.Process(t.Context(), job, func(context.Context, string) error { time.Sleep(200 * time.Millisecond); return nil })
	if e != nil || r.Status != protocol.Succeeded {
		t.Fatal(r, e)
	}
}

func TestLocalBudgetCapsServerBudget(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "agent"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p := policy.Default()
	p.TimeoutSeconds = 1
	job := task("local-budget")
	job.ExecutionTimeoutMS = 30000
	engine := Engine{State: s, Policy: p, Execute: func(ctx context.Context, _ protocol.Task, _ policy.Policy) (json.RawMessage, error) {
		deadline, _ := ctx.Deadline()
		if time.Until(deadline) > time.Second {
			t.Error("server widened local policy")
		}
		return goodPayload(), nil
	}}
	if _, e = engine.Process(t.Context(), job, start); e != nil {
		t.Fatal(e)
	}
}

// A subprocess exits without closing SQLite or the worker lock, exercising
// recovery from actual process termination, rather than only a clean Close.
func TestProcessCrashRecovery(t *testing.T) {
	if stage := os.Getenv("ARGUS_CRASH_TEST_STAGE"); stage != "" {
		dir := os.Getenv("ARGUS_CRASH_TEST_DIR")
		jobBytes, e := os.ReadFile(filepath.Join(dir, "task.json"))
		if e != nil {
			t.Fatal(e)
		}
		job, e := protocol.DecodeTask(jobBytes)
		if e != nil {
			t.Fatal(e)
		}
		s, e := OpenState(filepath.Join(dir, "state"), "node", true)
		if e != nil {
			t.Fatal(e)
		}
		die := func() { os.Exit(73) }
		if stage == "before_accept" {
			die()
		}
		engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
			if e := os.WriteFile(filepath.Join(dir, "collected"), []byte("once"), 0600); e != nil {
				t.Fatal(e)
			}
			if stage == "collecting" {
				die()
			}
			if stage == "completed_before_persist" {
				// Real collection finished; make the following persistence fail, then exit.
				if _, e := s.db.Exec("CREATE TRIGGER fail_result BEFORE UPDATE OF result ON executions BEGIN SELECT RAISE(FAIL,'disk failed'); END"); e != nil {
					t.Fatal(e)
				}
			}
			return goodPayload(), nil
		}}
		if stage == "running" {
			if _, e = s.prepare(t.Context(), job); e != nil {
				t.Fatal(e)
			}
			if e = s.markRunning(t.Context(), job.ID); e != nil {
				t.Fatal(e)
			}
			die()
		}
		_, e = engine.Process(t.Context(), job, func(context.Context, string) error {
			if stage == "accepted" {
				die()
			}
			return nil
		})
		if stage == "completed_before_persist" {
			if e == nil {
				t.Fatal("missing failure")
			}
			if _, e = s.db.Exec("DROP TRIGGER fail_result"); e != nil {
				t.Fatal(e)
			}
			die()
		}
		if e != nil {
			t.Fatal(e)
		}
		if stage == "acknowledged" {
			if e = s.Acknowledge(t.Context(), job.ID); e != nil {
				t.Fatal(e)
			}
		}
		die()
	}
	for _, stage := range []string{"before_accept", "accepted", "running", "collecting", "completed_before_persist", "persisted", "ack_received_not_saved", "acknowledged"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			job := task("crash-job")
			b, _ := json.Marshal(job)
			if e := os.WriteFile(filepath.Join(dir, "task.json"), b, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProcessCrashRecovery$")
			cmd.Env = append(os.Environ(), "ARGUS_CRASH_TEST_STAGE="+stage, "ARGUS_CRASH_TEST_DIR="+dir)
			output, e := cmd.CombinedOutput()
			var ex *exec.ExitError
			if !errors.As(e, &ex) || ex.ExitCode() != 73 {
				t.Fatalf("child: %v %s", e, output)
			}
			s, e := OpenState(filepath.Join(dir, "state"), "node", false)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			pending, e := s.Pending(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			if stage == "acknowledged" && len(pending) != 0 {
				t.Fatal("acknowledged result retransmitted")
			}
			if stage != "before_accept" && stage != "acknowledged" && len(pending) != 1 {
				t.Fatal("pending result lost", pending)
			}
			calls := 0
			engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
				calls++
				return goodPayload(), nil
			}}
			r, e := engine.Process(t.Context(), job, start)
			if e != nil {
				t.Fatal(e)
			}
			want := protocol.Unknown
			if stage == "before_accept" {
				if calls != 1 {
					t.Fatal("never accepted task not runnable")
				}
				want = protocol.Succeeded
			} else if calls != 0 {
				t.Fatal("reexecuted after crash")
			}
			if stage == "persisted" || stage == "ack_received_not_saved" || stage == "acknowledged" {
				want = protocol.Succeeded
			}
			if r.Status != want {
				t.Fatal(r, want)
			}
		})
	}
}

func TestClockChangesDoNotRestartOrExtendCollection(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	job := task("clock")
	job.ExecutionTimeoutMS = 80
	wall := time.Unix(job.CreatedAt, 0)
	engine := Engine{State: s, Policy: policy.Default(), now: func() time.Time { return wall }, Execute: func(ctx context.Context, _ protocol.Task, _ policy.Policy) (json.RawMessage, error) {
		wall = wall.Add(-24 * time.Hour)
		deadline, _ := ctx.Deadline()
		if remaining := time.Until(deadline); remaining > 80*time.Millisecond || remaining <= 0 {
			t.Error("wall clock changed elapsed budget", remaining)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	r, e := engine.Process(t.Context(), job, func(context.Context, string) error { wall = wall.Add(24 * time.Hour); return nil })
	if e != nil || r.Error != "collector_timeout" {
		t.Fatal(r, e)
	}
	future := task("future-clock")
	future.ExecutionTimeoutMS = 80
	r, e = engine.Process(t.Context(), future, start)
	// wall is back at original time after the simulated forward/backward changes.
	if e != nil || r.Error != "collector_timeout" {
		t.Fatal(r, e)
	}
}
