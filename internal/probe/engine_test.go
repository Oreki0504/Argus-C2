package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

type fixture struct {
	s         *State
	e         *Engine
	dir, path string
	node      identity.Node
	key       ed25519.PrivateKey
	p         policy.Policy
	calls     atomic.Int32
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{node: identity.New()}
	_, f.key, _ = ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	f.dir = filepath.Join(root, "state")
	f.path = filepath.Join(root, "policy.json")
	data, err := os.ReadFile("../../examples/task-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	f.p, err = policy.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	f.save(t)
	if err := Initialize(f.dir, f.node, f.key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	t.Cleanup(func() {
		if f.s != nil {
			f.s.Close()
		}
	})
	return f
}
func (f *fixture) save(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.s, err = Open(f.dir, f.node, f.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	f.e = NewEngine(f.s, f.path, "https://127.0.0.1:8443")
	f.e.execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		f.calls.Add(1)
		return []byte(`{"available":false,"os":"test","architecture":"test","hostname":"","kernel":"","boot_time":0}`), nil
	}
}
func (f *fixture) task() protocol.Task {
	digest, _ := f.p.Digest()
	now := time.Now().Unix()
	return protocol.Task{Version: 1, RequestID: identity.RandomID(), AgentID: f.node.AgentID, EnrollmentEpoch: f.node.EnrollmentEpoch, CreatedAt: now, ExpiresAt: now + 120, Type: protocol.SystemInfo, TaskVersion: 1, Params: json.RawMessage(`{}`), ActorID: "operator", PolicyDigest: digest}
}

// Sign arbitrary bytes to model a malicious server that possesses the real key.
func (f *fixture) sign(data []byte) []byte {
	sig := ed25519.Sign(f.key, append([]byte("argus-c2/task/v1\x00"), data...))
	b, _ := json.Marshal(map[string]string{"payload_b64": base64.RawURLEncoding.EncodeToString(data), "signature_b64": base64.RawURLEncoding.EncodeToString(sig)})
	return b
}
func (f *fixture) envelope(task protocol.Task) []byte { b, _ := json.Marshal(task); return f.sign(b) }
func result(t *testing.T, b []byte, err error) protocol.Result {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.DecodeResult(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDuplicateSurvivesRestartAndExpiration(t *testing.T) {
	f := setup(t)
	task := f.task()
	envelope := f.envelope(task)
	first, err := f.e.Process(t.Context(), envelope)
	r := result(t, first, err)
	if r.Status != protocol.Succeeded {
		t.Fatal(r)
	}
	if err := f.s.Acknowledge(t.Context(), task.RequestID, audit.Digest(first)); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s = nil
	f.open(t)
	payload, _ := json.Marshal(task)
	// The exact same signed task still returns its cached result after expiry.
	d, err := f.s.prepare(t.Context(), task, payload, f.p, "server", time.Unix(task.ExpiresAt+1, 0))
	if err != nil || d.run || !bytes.Equal(first, d.result) || f.calls.Load() != 1 {
		t.Fatalf("replayed: run=%v calls=%d err=%v", d.run, f.calls.Load(), err)
	}
}

func TestConcurrentAndConflictingRequestsDoNotExecuteTwice(t *testing.T) {
	f := setup(t)
	task := f.task()
	envelope := f.envelope(task)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	original := f.e.execute
	f.e.execute = func(ctx context.Context, task protocol.Task, p policy.Policy) (json.RawMessage, error) {
		close(entered)
		<-release
		return original(ctx, task, p)
	}
	go func() { _, err := f.e.Process(t.Context(), envelope); done <- err }()
	<-entered
	_, duplicateErr := f.e.Process(t.Context(), envelope)
	_, otherErr := f.e.Process(t.Context(), f.envelope(f.task()))
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(duplicateErr, ErrBusy) || !errors.Is(otherErr, ErrBusy) || f.calls.Load() != 1 {
		t.Fatalf("duplicate=%v other=%v calls=%d", duplicateErr, otherErr, f.calls.Load())
	}
	b, _ := json.Marshal(task)
	_, err := f.e.Process(t.Context(), f.sign(append([]byte(" "), b...)))
	if !errors.Is(err, ErrConflict) || f.calls.Load() != 1 {
		t.Fatalf("different original bytes: %v", err)
	}
}

func TestInterruptedIntentBecomesIndeterminate(t *testing.T) {
	f := setup(t)
	task := f.task()
	payload, _ := json.Marshal(task)
	d, err := f.s.prepare(t.Context(), task, payload, f.p, "server", time.Now())
	if err != nil || !d.run {
		t.Fatalf("prepare: %v", err)
	}
	if second, err := Open(f.dir, f.node, f.key.Public().(ed25519.PublicKey)); err == nil {
		second.Close()
		t.Fatal("second worker acquired live state")
	}
	f.s.Close()
	f.s = nil
	f.open(t)
	b, err := f.e.Process(t.Context(), f.envelope(task))
	r := result(t, b, err)
	if r.Status != protocol.Indeterminate || r.ErrorCode != "recovered_after_restart" || f.calls.Load() != 0 {
		t.Fatal(r)
	}
	page, err := ReadAudit(t.Context(), f.dir, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range page.Records {
		if record.Event.Kind == "task_recovered" {
			found = true
			if record.Event.ResultDigest != audit.Digest(b) {
				t.Fatal("unbound recovery result")
			}
		}
	}
	if !found {
		t.Fatal("missing recovery audit")
	}
}

func TestSignedServerCannotExpandLocalAuthority(t *testing.T) {
	for _, name := range []string{"paused", "disabled", "policy", "expired", "future", "type", "params", "epoch", "node", "timeout_field", "signature"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			task := f.task()
			want := protocol.Rejected
			code := ""
			switch name {
			case "paused":
				f.p.Paused = true
				f.save(t)
				task.PolicyDigest, _ = f.p.Digest()
				code = "paused"
			case "disabled":
				f.p.AllowSystemInfo = false
				f.save(t)
				task.PolicyDigest, _ = f.p.Digest()
				code = "task_disabled"
			case "policy":
				task.PolicyDigest = strings.Repeat("0", 64)
				code = "policy_mismatch"
			case "expired":
				task.CreatedAt -= 180
				task.ExpiresAt -= 180
				want = protocol.Expired
				code = "expired"
			case "future":
				task.CreatedAt += 120
				task.ExpiresAt += 120
				code = "future"
			case "type":
				task.Type = "shell.exec"
			case "params":
				task.Params = json.RawMessage(`{"path":"/etc/shadow"}`)
			case "epoch":
				task.EnrollmentEpoch = identity.RandomID()
			case "node":
				task.AgentID = identity.RandomID()
			}
			envelope := f.envelope(task)
			if name == "timeout_field" {
				raw, _ := json.Marshal(task)
				raw = append(raw[:len(raw)-1], []byte(`,"timeout_seconds":999}`)...)
				envelope = f.sign(raw)
			}
			if name == "signature" {
				envelope[len(envelope)-5] ^= 1
			}
			b, err := f.e.Process(t.Context(), envelope)
			if code != "" {
				r := result(t, b, err)
				if r.Status != want || string(r.ErrorCode) != code {
					t.Fatal(r)
				}
			} else if err == nil {
				t.Fatal("accepted invalid signed task")
			}
			if f.calls.Load() != 0 {
				t.Fatal("executed forbidden task")
			}
		})
	}
}

func TestPolicyReloadAndPersistentRateLimit(t *testing.T) {
	f := setup(t)
	f.p.MaxPerMinute = 1
	f.p.Burst = 1
	f.save(t)
	b, err := f.e.Process(t.Context(), f.envelope(f.task()))
	if result(t, b, err).Status != protocol.Succeeded {
		t.Fatal("first task failed")
	}
	f.s.Close()
	f.s = nil
	f.open(t)
	b, err = f.e.Process(t.Context(), f.envelope(f.task()))
	if r := result(t, b, err); r.ErrorCode != "rate_limited" {
		t.Fatal(r)
	}
	task := f.task()
	f.p.AllowSystemInfo = false
	f.save(t)
	b, err = f.e.Process(t.Context(), f.envelope(task))
	if r := result(t, b, err); r.ErrorCode != "policy_mismatch" {
		t.Fatal(r)
	}
	if f.calls.Load() != 1 {
		t.Fatal("rate limit lost across restart")
	}
}

func TestClockRollbackAndLostStateFailClosed(t *testing.T) {
	f := setup(t)
	future := time.Now().Add(2 * time.Minute)
	if err := f.s.Ready(t.Context(), f.p, future); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Ready(t.Context(), f.p, time.Now()); !errors.Is(err, ErrClock) {
		t.Fatal(err)
	}
	if err := f.s.Ready(t.Context(), f.p, future.Add(time.Second)); !errors.Is(err, ErrClock) {
		t.Fatal("rollback was not latched", err)
	}
	f.s.Close()
	f.s = nil
	if s, err := Open(f.dir, f.node, f.key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrClock) {
		if s != nil {
			s.Close()
		}
		t.Fatal(err)
	}
	if err := Initialize(f.dir, f.node, f.key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("reset existing replay state")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if s, err := Open(missing, f.node, f.key.Public().(ed25519.PublicKey)); err == nil {
		s.Close()
		t.Fatal("created missing state")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("missing directory was created")
	}
}

func TestStateBoundToIdentityAndKey(t *testing.T) {
	f := setup(t)
	f.s.Close()
	f.s = nil
	if s, err := Open(f.dir, identity.New(), f.key.Public().(ed25519.PublicKey)); err == nil {
		s.Close()
		t.Fatal("accepted different identity")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if s, err := Open(f.dir, f.node, other); err == nil {
		s.Close()
		t.Fatal("accepted different task key")
	}
	f.open(t)
}

func TestAuditFailurePreventsExecutionAndCompletionFailureRecovers(t *testing.T) {
	for _, stage := range []string{"task_accepted", "task_completed"} {
		t.Run(stage, func(t *testing.T) {
			f := setup(t)
			task := f.task()
			_, err := f.s.db.Exec("CREATE TRIGGER audit_failure BEFORE INSERT ON audit_events WHEN NEW.kind='" + stage + "' BEGIN SELECT RAISE(ABORT,'simulated full disk'); END;")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.e.Process(t.Context(), f.envelope(task)); err == nil {
				t.Fatal("ignored audit write failure")
			}
			want := int32(0)
			if stage == "task_completed" {
				want = 1
			}
			if f.calls.Load() != want {
				t.Fatalf("calls=%d", f.calls.Load())
			}
			if stage == "task_completed" {
				if err := f.s.Ready(t.Context(), f.p, time.Now()); !errors.Is(err, ErrBusy) {
					t.Fatal("unresolved execution advertised readiness", err)
				}
			}
			if _, err := f.s.db.Exec("DROP TRIGGER audit_failure"); err != nil {
				t.Fatal(err)
			}
			f.s.Close()
			f.s = nil
			f.open(t)
			b, err := f.e.Process(t.Context(), f.envelope(task))
			r := result(t, b, err)
			if stage == "task_completed" && r.Status != protocol.Indeterminate {
				t.Fatal(r)
			}
			if f.calls.Load() != 1 {
				t.Fatal("incorrect execution count after recovery")
			}
		})
	}
}

func TestPendingBudgetAndLocalDeadline(t *testing.T) {
	f := setup(t)
	f.p.MaxResultBytes = 1024
	f.p.PendingBytes = 1024
	f.p.TimeoutSeconds = 1
	f.save(t)
	f.e.execute = func(ctx context.Context, _ protocol.Task, _ policy.Policy) (json.RawMessage, error) {
		f.calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	b, err := f.e.Process(t.Context(), f.envelope(f.task()))
	r := result(t, b, err)
	if r.ErrorCode != "deadline" {
		t.Fatal(r)
	}
	if err := f.s.Ready(t.Context(), f.p, time.Now()); !errors.Is(err, ErrCapacity) {
		t.Fatal("pending budget not enforced", err)
	}
	if err := f.s.Acknowledge(t.Context(), r.RequestID, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong acknowledgment accepted")
	}
	if err := f.s.Acknowledge(t.Context(), r.RequestID, audit.Digest(b)); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Ready(t.Context(), f.p, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestResultLimitAndMissingExecutionRowFailClosed(t *testing.T) {
	f := setup(t)
	f.p.MaxResultBytes = 1024
	f.save(t)
	f.e.execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		f.calls.Add(1)
		return json.Marshal(protocol.SystemInformation{Available: true, OS: strings.Repeat("x", 32), Architecture: strings.Repeat("x", 32), Hostname: strings.Repeat("x", 255), Kernel: strings.Repeat("x", 255), BootTime: time.Now().Unix() - 100})
	}
	task := f.task()
	b, err := f.e.Process(t.Context(), f.envelope(task))
	r := result(t, b, err)
	if r.ErrorCode != "result_limit" || len(b) > 1024 {
		t.Fatal(r, len(b))
	}
	// An intact audit decision prevents rerunning even if its execution row was lost.
	if _, err := f.s.db.Exec("DELETE FROM executions WHERE request_id=?", task.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Process(t.Context(), f.envelope(task)); err == nil {
		t.Fatal("lost row caused rerun")
	}
	if f.calls.Load() != 1 {
		t.Fatal("executed again")
	}
}
