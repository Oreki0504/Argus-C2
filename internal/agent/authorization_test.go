package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func TestRunningAuthorizationFailureEventuallyReconciles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		status  protocol.TaskStatus
	}{
		{"conflict", &transport.APIError{Status: 409, Code: "state_conflict"}, protocol.Failed},
		{"expired-or-pruned", &transport.APIError{Status: 404, Code: "task_not_found"}, protocol.Failed},
		{"timeout", context.DeadlineExceeded, protocol.Unknown},
		{"disconnect", io.ErrUnexpectedEOF, protocol.Unknown},
		{"unclassified-conflict", &transport.APIError{Status: 409}, protocol.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s, err := OpenState(dir, "node", true)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			calls, grants := 0, 0
			engine := &Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
				calls++
				return goodPayload(), nil
			}}
			job := task("grant-failed")
			if _, err = engine.Process(t.Context(), job, func(context.Context, string) error { grants++; return tc.failure }); !errors.Is(err, tc.failure) {
				t.Fatal(err)
			}
			// No redelivery or restart is required to make this result uploadable.
			pending, err := s.Pending(t.Context())
			if err != nil || len(pending) != 1 || pending[0].Status != tc.status {
				t.Fatal(pending, err)
			}
			var reserved int
			if err = s.db.QueryRow("SELECT count(*) FROM executions WHERE result='' AND delivery='pending'").Scan(&reserved); err != nil || reserved != 0 {
				t.Fatal("reservation leaked", reserved, err)
			}
			if err = s.Acknowledge(t.Context(), job.ID); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = OpenState(dir, "node", false)
			if err != nil {
				t.Fatal(err)
			}
			engine.State = s
			result, err := engine.Process(t.Context(), job, func(context.Context, string) error { grants++; return nil })
			if err != nil || result.Status != tc.status || grants != 1 || calls != 0 {
				t.Fatal(result, err, grants, calls)
			}
		})
	}
}

func TestGrantFailurePersistenceBarrierRecoversWithoutRedelivery(t *testing.T) {
	s, err := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec("CREATE TRIGGER fail BEFORE UPDATE ON executions BEGIN SELECT RAISE(FAIL,'disk unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	engine := &Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		t.Fatal("collected across persistence barrier")
		return nil, nil
	}}
	job := task("failed")
	ctx, cancel := context.WithCancel(t.Context())
	if _, err = engine.Process(ctx, job, func(context.Context, string) error { cancel(); return context.DeadlineExceeded }); err == nil {
		t.Fatal("error hidden")
	}
	if _, err = engine.Process(t.Context(), task("new"), start); err == nil {
		t.Fatal("new task bypassed recovery")
	}
	if _, err = s.db.Exec("DROP TRIGGER fail"); err != nil {
		t.Fatal(err)
	}
	if err = s.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, err := s.Pending(t.Context())
	if err != nil || len(pending) != 1 || pending[0].Status != protocol.Unknown {
		t.Fatal(pending, err)
	}
}
