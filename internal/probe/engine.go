package probe

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/signing"
	"github.com/Oreki0504/Argus-C2/internal/tasks"
)

type Engine struct {
	state              *State
	policyPath, source string
	execute            func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error)
}

func NewEngine(s *State, policyPath, source string) *Engine {
	return &Engine{state: s, policyPath: policyPath, source: source, execute: tasks.Execute}
}

func (e *Engine) Process(ctx context.Context, envelope []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t, payload, err := signing.VerifyPayload(envelope, e.state.key)
	if err != nil || t.AgentID != e.state.node.AgentID || t.EnrollmentEpoch != e.state.node.EnrollmentEpoch {
		if len(envelope) > protocol.MaxEnvelopeBytes {
			envelope = envelope[:protocol.MaxEnvelopeBytes]
		}
		if err := e.state.rejectInvalid(ctx, audit.Digest(envelope), e.source); err != nil {
			return nil, err
		}
		return nil, errors.New("task failed signature, structure, or target checks")
	}
	p, err := policy.Load(e.policyPath)
	if err != nil {
		return nil, err
	}
	d, err := e.state.prepare(ctx, t, payload, p, e.source, time.Now())
	if err != nil {
		return nil, err
	}
	if !d.run {
		return d.result, nil
	}
	end := time.Now().Add(time.Duration(p.TimeoutSeconds) * time.Second)
	if expires := time.Unix(t.ExpiresAt, 0); expires.Before(end) {
		end = expires
	}
	r := emptyResult(t, d.digest, d.started, d.started, protocol.Failed, "collector_failed")
	if time.Now().Unix() >= t.ExpiresAt {
		r.Status = protocol.Expired
		r.ErrorCode = "expired"
	} else {
		taskCtx, cancel := context.WithDeadline(ctx, end)
		data, collectErr := e.execute(taskCtx, t, p)
		contextErr := taskCtx.Err()
		cancel()
		if collectErr != nil || contextErr != nil {
			if errors.Is(collectErr, context.DeadlineExceeded) || errors.Is(collectErr, context.Canceled) || contextErr != nil {
				r.ErrorCode = "deadline"
			}
		} else {
			r.Status = protocol.Succeeded
			r.ErrorCode = ""
			r.Data = data
		}
	}
	r.FinishedAt = max(r.StartedAt, time.Now().Unix())
	if err := errors.Join(r.Validate(), r.CheckAssignment(t)); err != nil {
		r.Status = protocol.Failed
		r.ErrorCode = "collector_failed"
		r.Data = json.RawMessage(`{}`)
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(data) > p.MaxResultBytes {
		r.Status = protocol.Failed
		r.ErrorCode = "result_limit"
		r.Data = json.RawMessage(`{}`)
	}
	// Cancellation may stop collection, but recording its terminal outcome must
	// still be attempted. Failure leaves a running record for crash recovery.
	finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return e.state.finish(finishCtx, t, r, e.source)
}
