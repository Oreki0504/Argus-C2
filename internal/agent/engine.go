package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/collectors"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

type Engine struct {
	now     func() time.Time
	State   *State
	Policy  policy.Policy
	Execute func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error)
}

func (e *Engine) Process(ctx context.Context, t protocol.Task, running func(context.Context, string) error) (protocol.Result, error) {
	e.State.mu.Lock()
	defer e.State.mu.Unlock()
	if err := t.Validate(); err != nil {
		return protocol.Result{}, err
	}
	if t.NodeID != e.State.NodeID {
		return protocol.Result{}, errors.New("task belongs to another node")
	}
	if err := e.Policy.Validate(); err != nil {
		return protocol.Result{}, err
	}
	old, err := e.State.prepare(ctx, t)
	if err != nil {
		return protocol.Result{}, err
	}
	if old != nil {
		return *old, nil
	}
	r := protocol.NewResult(t, protocol.Failed, "collector_failed")
	now := time.Now()
	if e.now != nil {
		now = e.now()
	}
	switch {
	case t.DispatchExpiresAt <= now.Unix():
		r.Error = "task_expired"
	case t.CreatedAt > now.Unix()+protocol.MaxClockSkew:
		r.Error = "task_from_future"
	case !e.Policy.Allows(t):
		r.Error = "local_policy_denied"
	default:
		if err = running(ctx, t.ID); err != nil {
			return protocol.Result{}, err
		}
		if err = e.State.markRunning(ctx, t.ID); err != nil {
			e.State.interruption(t, "running_persistence_interrupted")
			finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return protocol.Result{}, errors.Join(err, e.State.recover(finishCtx))
		}
		// The collector gets its full bounded duration after authorization and
		// durable intent. Dispatch expiry never truncates an authorized execution.
		budget := min(time.Duration(t.ExecutionTimeoutMS)*time.Millisecond, time.Duration(e.Policy.TimeoutSeconds)*time.Second)
		taskCtx, cancel := context.WithTimeout(ctx, budget)
		execute := e.Execute
		if execute == nil {
			execute = collectors.Execute
		}
		payload, collectErr := execute(taskCtx, t, e.Policy)
		contextErr := taskCtx.Err()
		cancel()
		if collectErr == nil && contextErr == nil {
			r.Status = protocol.Succeeded
			r.Error = ""
			r.Payload = payload
		} else if contextErr != nil {
			r.Error = "collector_timeout"
		}
	}
	r.CompletedAt = time.Now().Unix()
	if err = errors.Join(r.Validate(), r.CheckAssignment(t)); err != nil {
		r = protocol.NewResult(t, protocol.Failed, "invalid_collector_output")
	}
	b, _ := json.Marshal(r)
	if len(b) > e.Policy.MaxResultBytes {
		r = protocol.NewResult(t, protocol.Failed, "result_too_large")
	}
	finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = e.State.finish(finishCtx, r)
	if err != nil {
		e.State.interruption(t, "result_persistence_interrupted")
	}
	return r, err
}
