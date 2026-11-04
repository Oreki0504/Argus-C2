package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type Runner struct {
	Server, CA, Dir string
	Client          *http.Client
	Engine          *Engine
	cert            *x509.Certificate
}

func Open(server, ca, dir string, p policy.Policy) (*Runner, error) {
	if e := transport.ValidateURL(server); e != nil {
		return nil, e
	}
	if e := p.Validate(); e != nil {
		return nil, e
	}
	pair, e := transport.Pair(filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	id, e := identity.FromCertificate(cert)
	if e != nil {
		return nil, e
	}
	key, e := loadKey(filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(filepath.Join(dir, "agent.pem"))
	if e != nil {
		return nil, e
	}
	if _, e = verifyCertificate(string(b), key, ca, id); e != nil {
		return nil, e
	}
	state, e := OpenState(dir, id, false)
	if e != nil {
		return nil, e
	}
	client, e := transport.Client(ca, filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		state.Close()
		return nil, e
	}
	return &Runner{server, ca, dir, client, &Engine{State: state, Policy: p}, cert}, nil
}
func (r *Runner) Close() error { r.Client.CloseIdleConnections(); return r.Engine.State.Close() }
func (r *Runner) request(ctx context.Context, path string, v any) ([]byte, error) {
	return transport.Request(ctx, r.Client, r.Server, "", "POST", path, v)
}
func (r *Runner) flush(ctx context.Context) error {
	// Bound one upload batch independently of the number of pending results.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pending, e := r.Engine.State.Pending(ctx)
	if e != nil {
		return e
	}
	for _, result := range pending {
		if e = r.upload(ctx, result); e != nil {
			return e
		}
	}
	return nil
}
func (r *Runner) upload(ctx context.Context, result protocol.Result) error {
	b, e := r.request(ctx, "/v1/agent/results", result)
	if e != nil {
		var apiError *transport.APIError
		if errors.As(e, &apiError) && apiError.ResultRejection() {
			if e = r.Engine.State.Hold(ctx, result.TaskID, apiError.Code); e != nil {
				return e
			}
			slog.Warn("result requires operator attention", "task_id", result.TaskID, "code", apiError.Code)
			return nil
		}
		return e
	}
	// An arbitrary 2xx page is not an acknowledgment.
	if e = strictjson.Decode(b, &struct{}{}, 256); e != nil {
		return errors.New("invalid result acknowledgment")
	}
	return r.Engine.State.Acknowledge(ctx, result.TaskID)
}
func (r *Runner) Step(ctx context.Context) error {
	if e := r.Engine.State.Recover(ctx); e != nil {
		return e
	}
	if time.Until(r.cert.NotAfter) < 7*24*time.Hour {
		if e := r.Renew(ctx); e != nil {
			return e
		}
	}
	flushErr := r.flush(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	host, e := os.Hostname()
	if e != nil {
		return e
	}
	if _, e = r.request(ctx, "/v1/agent/heartbeat", protocol.Heartbeat{Hostname: host}); e != nil {
		return e
	}
	// Heartbeat still runs after an upload failure. Do not accept fresh work
	// until a transient/identity/protocol error has been resolved.
	if flushErr != nil {
		return flushErr
	}
	b, e := r.request(ctx, "/v1/agent/poll", struct{}{})
	if e != nil || len(b) == 0 {
		return e
	}
	t, e := protocol.DecodeTask(b)
	if e != nil {
		return e
	}
	result, e := r.Engine.Process(ctx, t, func(ctx context.Context, id string) error {
		b, e := r.request(ctx, "/v1/agent/tasks/"+id+"/running", struct{}{})
		if e != nil {
			return e
		}
		if strictjson.Decode(b, &struct{}{}, 256) != nil {
			return errors.New("invalid execution authorization response")
		}
		return nil
	})
	if errors.Is(e, ErrCapacity) || errors.Is(e, ErrResultHeld) || errors.Is(e, ErrResultDiscarded) {
		slog.Warn("task deferred locally", "task_id", t.ID, "reason", e)
		return nil
	}
	if e != nil {
		return e
	}
	return r.upload(ctx, result)
}
func (r *Runner) Renew(ctx context.Context) error {
	key, e := loadKey(filepath.Join(r.Dir, "agent-key.pem"))
	if e != nil {
		return e
	}
	csr, e := enrollment.CSR(key)
	if e != nil {
		return e
	}
	b, e := r.request(ctx, "/v1/agent/renew", protocol.RenewalRequest{CSR: csr})
	if e != nil {
		return e
	}
	var response protocol.EnrollmentResponse
	if e = json.Unmarshal(b, &response); e != nil {
		return e
	}
	if response.NodeID != r.Engine.State.NodeID {
		return errors.New("renewal changed identity")
	}
	cert, e := verifyCertificate(response.Certificate, key, r.CA, response.NodeID)
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(r.Dir, "agent.pem"), []byte(response.Certificate)); e != nil {
		return e
	}
	client, e := transport.Client(r.CA, filepath.Join(r.Dir, "agent.pem"), filepath.Join(r.Dir, "agent-key.pem"))
	if e != nil {
		return e
	}
	r.Client.CloseIdleConnections()
	r.Client = client
	r.cert = cert
	return nil
}
func (r *Runner) Run(ctx context.Context) error {
	delay := time.Duration(r.Engine.Policy.PollSeconds) * time.Second
	for {
		e := r.Step(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if e != nil {
			slog.Warn("agent cycle failed; will retry", "error", e)
			delay = min(60*time.Second, max(5*time.Second, delay*2))
		} else {
			delay = time.Duration(r.Engine.Policy.PollSeconds) * time.Second
		}
		timer := time.NewTimer(delay + time.Duration(rand.IntN(1000))*time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
