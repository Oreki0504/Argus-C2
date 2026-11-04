package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func pendingResult(t *testing.T, f *fleet, r *agent.Runner) (protocol.Task, protocol.Result) {
	t.Helper()
	job := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
	raw, e := transport.Request(t.Context(), r.Client, f.url, "", "POST", "/v1/agent/poll", struct{}{})
	if e != nil {
		t.Fatal(e)
	}
	delivered, e := protocol.DecodeTask(raw)
	if e != nil {
		t.Fatal(e)
	}
	result, e := r.Engine.Process(t.Context(), delivered, func(ctx context.Context, id string) error {
		_, e := transport.Request(ctx, r.Client, f.url, "", "POST", "/v1/agent/tasks/"+id+"/running", struct{}{})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return job, result
}
func nodeCertificate(t *testing.T, r *agent.Runner) *x509.Certificate {
	t.Helper()
	pair, e := transport.Pair(filepath.Join(r.Dir, "agent.pem"), filepath.Join(r.Dir, "agent-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	return cert
}
func TestResultErrorClassificationAndHeartbeat(t *testing.T) {
	cases := []struct {
		name           string
		status         int
		body, delivery string
	}{
		{"conflict", 409, `{"code":"result_conflict","error":"conflict"}`, "held"},
		{"rejected", 409, `{"code":"task_rejected","error":"rejected"}`, "held"},
		{"missing", 404, `{"code":"task_not_found","error":"missing"}`, "held"},
		{"invalid", 400, `{"code":"result_invalid","error":"invalid"}`, "held"},
		{"generic_conflict", 409, `{"code":"state_conflict","error":"conflict"}`, "pending"},
		{"unknown_404", 404, `not found`, "pending"},
		{"server_error", 500, `{"code":"operation_failed","error":"failure"}`, "pending"},
		{"misclassified_500", 500, `{"code":"result_conflict","error":"failure"}`, "pending"},
		{"unauthorized", 401, `{"code":"unauthorized","error":"denied"}`, "pending"},
		{"forbidden", 403, `{"code":"forbidden","error":"denied"}`, "pending"},
		{"unknown_code", 400, `{"code":"unexpected-secret","error":"SECRET"}`, "pending"},
		{"malformed_ack", 200, `<html>success</html>`, "pending"},
		{"empty_ack", 204, ``, "pending"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFleet(t)
			r := f.enroll("agent", policy.Default())
			job, _ := pendingResult(t, f, r)
			original := r.Client.Transport
			r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/v1/agent/results" {
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}, protocol.VersionHeader: []string{"1"}}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: req}, nil
				}
				return original.RoundTrip(req)
			})
			e := r.Step(t.Context())
			if tc.delivery == "pending" && e == nil {
				t.Fatal("response mistaken for acknowledgment")
			}
			if tc.delivery == "held" && e != nil {
				t.Fatal(e)
			}
			record, e := r.Engine.State.Delivery(t.Context(), job.ID)
			if e != nil || record.Delivery != tc.delivery || record.Bytes == 0 {
				t.Fatal(record, e)
			}
			nodes, e := f.store.Nodes(t.Context(), "")
			if e != nil || nodes[0].LastSeenAt == 0 {
				t.Fatal("upload blocked heartbeat", e)
			}
			r.Client.Transport = original
			if tc.delivery == "held" {
				if e = r.Engine.State.Retry(t.Context(), job.ID); e != nil {
					t.Fatal(e)
				}
			}
			if e = r.Step(t.Context()); e != nil {
				t.Fatal("recovery failed", e)
			}
			record, e = r.Engine.State.Delivery(t.Context(), job.ID)
			if e != nil || record.Delivery != "acknowledged" {
				t.Fatal(record, e)
			}
		})
	}
}
func TestPermanentResultFailureDoesNotBlockNewWork(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	old, _ := pendingResult(t, f, r)
	if _, e := f.store.DB.Exec("DELETE FROM tasks WHERE id=?", old.ID); e != nil {
		t.Fatal(e)
	}
	next := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
	if e := r.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	record, e := r.Engine.State.Delivery(t.Context(), old.ID)
	if e != nil || record.Delivery != "held" || record.Reason != "task_not_found" {
		t.Fatal(record, e)
	}
	view, e := f.store.Task(t.Context(), next.ID)
	if e != nil || view.Result == nil || view.Task.Status != protocol.Succeeded {
		t.Fatal("old missing result blocked collection", view, e)
	}
}

func TestSlowResultUploadLeavesTimeForHeartbeat(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job, _ := pendingResult(t, f, r)
	original := r.Client.Transport
	r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v1/agent/results" {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		return original.RoundTrip(req)
	})
	defer func() { r.Client.Transport = original }()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	started := time.Now()
	err := r.Step(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || time.Since(started) > 15*time.Second {
		t.Fatal("upload exhausted the whole cycle", err, ctx.Err(), time.Since(started))
	}
	nodes, err := f.store.Nodes(t.Context(), "")
	if err != nil || len(nodes) != 1 || nodes[0].LastSeenAt == 0 {
		t.Fatal("slow upload prevented heartbeat", nodes, err)
	}
	record, err := r.Engine.State.Delivery(t.Context(), job.ID)
	if err != nil || record.Delivery != "pending" || record.Bytes == 0 {
		t.Fatal("timed-out upload lost report", record, err)
	}
	r.Client.Transport = original
	if err = r.Step(t.Context()); err != nil {
		t.Fatal("upload failed after network recovery", err)
	}
}
func TestCommittedResultLostResponseSurvivesRestart(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job, result := pendingResult(t, f, r)
	original := r.Client.Transport
	var uploads atomic.Int32
	r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		response, e := original.RoundTrip(req)
		if req.URL.Path == "/v1/agent/results" && e == nil && uploads.Add(1) == 1 {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			return nil, errors.New("injected lost response")
		}
		return response, e
	})
	if e := r.Step(t.Context()); e == nil {
		t.Fatal("lost response hidden")
	}
	view, e := f.store.Task(t.Context(), job.ID)
	if e != nil || view.Result == nil {
		t.Fatal("server did not commit", e)
	}
	r.Client.Transport = original
	r.Engine.State.Close()
	state, e := agent.OpenState(r.Dir, r.Engine.State.NodeID, false)
	if e != nil {
		t.Fatal(e)
	}
	r.Engine.State = state
	r.Engine.Execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		t.Error("replayed committed collection")
		return nil, nil
	}
	if e = r.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	pending, e := state.Pending(t.Context())
	if e != nil || len(pending) != 0 {
		t.Fatal(pending, e)
	}
	view, e = f.store.Task(t.Context(), job.ID)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := protocol.EquivalentResults(view.Task, result, *view.Result); e != nil || !ok {
		t.Fatal("result changed", e)
	}
}
func TestConcurrentLateResultsAndTimeout(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job, result := pendingResult(t, f, r)
	cert := nodeCertificate(t, r)
	if _, e := f.store.DB.Exec("UPDATE tasks SET result_due_at=? WHERE id=?", time.Now().Unix()-1, job.ID); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			if e := f.store.SubmitResult(t.Context(), cert, result); e != nil {
				t.Error(e)
			}
		})
		wg.Go(func() {
			if _, e := f.store.Task(t.Context(), job.ID); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	view, e := f.store.Task(t.Context(), job.ID)
	if e != nil || view.Task.Status != protocol.Succeeded || view.Result == nil {
		t.Fatal(view, e)
	}
	var completions int
	if e = f.store.DB.QueryRow("SELECT count(*) FROM audit_events WHERE task_id=? AND action='task.complete'", job.ID).Scan(&completions); e != nil || completions != 1 {
		t.Fatal("duplicate commits", completions, e)
	}
	changed := result
	changed.CompletedAt++
	if e = f.store.SubmitResult(t.Context(), cert, changed); !errors.Is(e, database.ErrResultConflict) {
		t.Fatal("conflicting late result accepted", e)
	}
}
func TestConflictingUploadsHaveOneWinner(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job, result := pendingResult(t, f, r)
	cert := nodeCertificate(t, r)
	other := protocol.NewResult(job, protocol.Failed, "different")
	var successes, conflicts atomic.Int32
	var wg sync.WaitGroup
	for _, value := range []protocol.Result{result, other} {
		wg.Go(func() {
			e := f.store.SubmitResult(t.Context(), cert, value)
			if e == nil {
				successes.Add(1)
			} else if errors.Is(e, database.ErrResultConflict) {
				conflicts.Add(1)
			} else {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 || conflicts.Load() != 1 {
		t.Fatal(successes.Load(), conflicts.Load())
	}
}
func TestDispatchExpiryDoesNotShortenAuthorizedCollection(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
	cert := nodeCertificate(t, r)
	delivered, e := f.store.Poll(t.Context(), cert)
	if e != nil || delivered == nil {
		t.Fatal(e)
	}
	if e = f.store.Running(t.Context(), cert, job.ID); e != nil {
		t.Fatal(e)
	}
	before, e := f.store.Task(t.Context(), job.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec("UPDATE tasks SET dispatch_expires_at=? WHERE id=?", time.Now().Unix()-1, job.ID); e != nil {
		t.Fatal(e)
	}
	if e = f.store.Running(t.Context(), cert, job.ID); e != nil {
		t.Fatal("authorization retry lost", e)
	}
	after, e := f.store.Task(t.Context(), job.ID)
	if e != nil || after.Task.Status != protocol.Running || after.Task.ResultDueAt != before.Task.ResultDueAt {
		t.Fatal("dispatch expiry changed running budget", after, e)
	}
	if _, e = f.store.DB.Exec("UPDATE tasks SET result_due_at=? WHERE id=?", time.Now().Unix()-1, job.ID); e != nil {
		t.Fatal(e)
	}
	inferred, e := f.store.Task(t.Context(), job.ID)
	if e != nil || inferred.Task.Status != protocol.Unknown || inferred.Result != nil {
		t.Fatal(inferred, e)
	}
	result := protocol.NewResult(job, protocol.Failed, "collector_timeout")
	for range 2 {
		if e = f.store.SubmitResult(t.Context(), cert, result); e != nil {
			t.Fatal("late result rejected", e)
		}
	}
}

func TestProtocolVersionCheckedOnEveryAgentRequest(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job, _ := pendingResult(t, f, r)
	original := r.Client.Transport
	// Keep the same underlying transport/pooled connection while changing metadata.
	r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.Header.Set(protocol.VersionHeader, "999")
		return original.RoundTrip(req)
	})
	e := r.Step(t.Context())
	wantStatus(t, e, 426)
	record, e := r.Engine.State.Delivery(t.Context(), job.ID)
	if e != nil || record.Delivery != "pending" {
		t.Fatal("incompatible upload lost state", record, e)
	}
	r.Client.Transport = original
	if e = r.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	nodes, e := f.store.Nodes(t.Context(), "")
	if e != nil || nodes[0].ProtocolVersion != protocol.Version || nodes[0].AgentVersion != protocol.BuildVersion() {
		t.Fatal(nodes, e)
	}
	// A registered agent may not poll on a new connection without metadata either.
	r.Client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(t.Context(), "POST", f.url+"/v1/agent/poll", strings.NewReader("{}"))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := r.Client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 426 {
		t.Fatal(response.StatusCode)
	}
	// An incompatible server response is rejected before task acceptance.
	next := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
	r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		res, e := original.RoundTrip(req)
		if e == nil && req.URL.Path == "/v1/agent/poll" {
			res.Header.Set(protocol.VersionHeader, "999")
		}
		return res, e
	})
	if e = r.Step(t.Context()); e == nil {
		t.Fatal("accepted unsupported response")
	}
	records, e := r.Engine.State.Deliveries(t.Context(), "")
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range records {
		if v.TaskID == next.ID {
			t.Fatal("persisted incompatible task")
		}
	}
	r.Client.Transport = original
}

func TestDisableRejectsRenewalAndPreviousIdentity(t *testing.T) {
	f := newFleet(t)
	f.issuer.Lifetime = 2 * time.Hour
	r := f.enroll("agent", policy.Default())
	old, e := transport.Client(r.CA, filepath.Join(r.Dir, "agent.pem"), filepath.Join(r.Dir, "agent-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	defer old.CloseIdleConnections()
	_, e = transport.Request(t.Context(), old, f.url, "", "POST", "/v1/agent/poll", struct{}{})
	if e != nil {
		t.Fatal(e)
	}
	f.issuer.Lifetime = 30 * 24 * time.Hour
	if e = r.Renew(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e = f.store.Disable(t.Context(), "admin", r.Engine.State.NodeID); e != nil {
		t.Fatal(e)
	}
	for _, client := range []*http.Client{old, r.Client} {
		_, e = transport.Request(t.Context(), client, f.url, "", "POST", "/v1/agent/poll", struct{}{})
		wantStatus(t, e, 401)
	}
	if e = r.Renew(t.Context()); e == nil {
		t.Fatal("disabled identity renewed")
	} else {
		wantStatus(t, e, 401)
	}
	fresh := f.enroll("new-identity", policy.Default())
	if fresh.Engine.State.NodeID == r.Engine.State.NodeID {
		t.Fatal("reenrollment reused revoked identity")
	}
	if e = fresh.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
}

func TestDisableSerializesWithGrantRenewalAndResult(t *testing.T) {
	for _, action := range []string{"grant", "renew", "result"} {
		t.Run(action, func(t *testing.T) {
			f := newFleet(t)
			f.issuer.Lifetime = 2 * time.Hour
			r := f.enroll("agent", policy.Default())
			cert := nodeCertificate(t, r)
			job := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
			if _, err := f.store.Poll(t.Context(), cert); err != nil {
				t.Fatal(err)
			}
			keyBytes, err := os.ReadFile(filepath.Join(r.Dir, "agent-key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(keyBytes)
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := enrollment.CSR(key.(*ecdsa.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			f.issuer.Lifetime = 30 * 24 * time.Hour
			result := protocol.NewResult(job, protocol.Failed, "local_policy_denied")
			operation := func() error {
				switch action {
				case "grant":
					return f.store.Running(t.Context(), cert, job.ID)
				case "renew":
					_, err := (enrollment.Service{Store: f.store, Issuer: f.issuer}).Renew(t.Context(), cert, csr)
					return err
				default:
					return f.store.SubmitResult(t.Context(), cert, result)
				}
			}
			ready := make(chan struct{})
			disabled, operated := make(chan error, 1), make(chan error, 1)
			go func() { <-ready; disabled <- f.store.Disable(t.Context(), "admin", r.Engine.State.NodeID) }()
			go func() { <-ready; operated <- operation() }()
			close(ready)
			if err = <-disabled; err != nil {
				t.Fatal(err)
			}
			opErr := <-operated
			if opErr != nil && !errors.Is(opErr, database.ErrUnauthorized) {
				t.Fatal("unexpected race outcome", opErr)
			}
			if err = operation(); !errors.Is(err, database.ErrUnauthorized) {
				t.Fatal("operation authorized after disable committed", err)
			}
			view, err := f.store.Task(t.Context(), job.ID)
			if err != nil || view.Result == nil {
				t.Fatal(view, err)
			}
			if action == "result" && opErr == nil {
				if equal, err := protocol.EquivalentResults(job, *view.Result, result); err != nil || !equal {
					t.Fatal("disable overwrote previously committed report", err)
				}
			} else if view.Result.Status != protocol.Unknown || view.Result.Error != "node_disabled" {
				t.Fatal("in-flight disable outcome lost", view)
			}
		})
	}
}

func TestRestoreRequiresReapplyingPostSnapshotRevocation(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	node := r.Engine.State.NodeID
	cert := nodeCertificate(t, r)
	job := f.task(node, protocol.SystemInfo, "{}")
	if e := r.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	backupDir := filepath.Join(f.dir, "restore")
	if e := os.Mkdir(backupDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := f.store.Backup(t.Context(), filepath.Join(backupDir, "argus.db")); e != nil {
		t.Fatal(e)
	}
	if e := f.store.Disable(t.Context(), "admin", node); e != nil {
		t.Fatal(e)
	}
	// Closing the test listener is the isolation boundary. No restored state is
	// reachable over the network until revocations are reapplied and checked.
	address := f.server.Listener.Addr().String()
	f.server.Close()
	f.store.Close()
	if e := r.Step(t.Context()); e == nil {
		t.Fatal("agent accessed isolated restore")
	}
	restored, e := database.Open(backupDir, false)
	if e != nil {
		t.Fatal(e)
	}
	f.store = restored
	var status string
	if e = restored.DB.QueryRow("SELECT status FROM nodes WHERE id=?", node).Scan(&status); e != nil || status != "active" {
		t.Fatal("fixture did not restore older identity", status, e)
	}
	if _, e = f.admins.Authenticate(f.adminToken); e != nil {
		t.Fatal(e)
	}
	if user, e := f.admins.Authenticate(f.readToken); e != nil || user.Role != "ReadOnly" {
		t.Fatal(user, e)
	}
	if e = restored.Disable(t.Context(), "restore-operator", node); e != nil {
		t.Fatal(e)
	}
	if _, e = restored.Authorize(t.Context(), cert); !errors.Is(e, database.ErrUnauthorized) {
		t.Fatal("revocation not restored", e)
	}
	view, e := restored.Task(t.Context(), job.ID)
	if e != nil || view.Result == nil || view.Task.Status != protocol.Succeeded {
		t.Fatal("committed snapshot result lost", view, e)
	}
	f.start(address)
	if e = r.Step(t.Context()); e == nil {
		t.Fatal("revoked node reconnected after restore")
	} else {
		wantStatus(t, e, 401)
	}
}

func TestIncompatibleEnrollmentDoesNotConsumeToken(t *testing.T) {
	f := newFleet(t)
	token, e := f.store.CreateToken(t.Context(), "admin", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := enrollment.CSR(key)
	if e != nil {
		t.Fatal(e)
	}
	request := protocol.EnrollmentRequest{Token: token, Hostname: "version", CSR: csr}
	b, _ := json.Marshal(request)
	req, e := http.NewRequestWithContext(t.Context(), "POST", f.url+"/v1/enroll", strings.NewReader(string(b)))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.VersionHeader, "999")
	req.Header.Set(protocol.AgentVersionHeader, "development")
	res, e := f.client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 426 {
		t.Fatal(res.StatusCode)
	}
	nodes, e := f.store.Nodes(t.Context(), "")
	if e != nil || len(nodes) != 0 {
		t.Fatal("incompatible enrollment persisted identity", e)
	}
	f.call("", "POST", "/v1/enroll", request)
}
