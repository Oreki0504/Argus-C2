package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func TestMTLSTaskLifecycleAndLocalPolicy(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	service, err := server.NewTaskService(t.Context(), f.store, key)
	if err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(f.root, "pki")
	config, err := tlsconfig.Server(tlsconfig.Files{Certificate: filepath.Join(pki, "server-cert.pem"), PrivateKey: filepath.Join(pki, "server-key.pem"), CA: f.ca}, f.store)
	if err != nil {
		t.Fatal(err)
	}
	s := start(t, config, server.Handler(f.store, service))
	c, err := agent.NewClient(s.URL, f.clientTLS, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	policyBytes, err := os.ReadFile("../../examples/task-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Decode(policyBytes)
	if err != nil {
		t.Fatal(err)
	}
	p.Telemetry.SampleMilliseconds = 100
	policyBytes, _ = json.Marshal(p)
	path := filepath.Join(f.root, "policy.json")
	if err := os.WriteFile(path, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.root, "replay")
	if err := probe.Initialize(dir, f.node, pub); err != nil {
		t.Fatal(err)
	}
	worker, err := probe.Open(dir, f.node, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if worker != nil {
			worker.Close()
		}
	}()
	// The running client advertises readiness and completes an empty poll.
	if err := c.RunTasks(t.Context(), path, worker, true, nil); err != nil {
		t.Fatal(err)
	}
	digest, _ := p.Digest()
	engine := probe.NewEngine(worker, path, s.URL)
	for _, kind := range []protocol.TaskType{protocol.SystemInfo, protocol.SystemMetrics} {
		task, err := f.store.Enqueue(t.Context(), f.node.AgentID, kind, "integration-operator", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := c.Poll(t.Context(), digest)
		if err != nil || len(envelope) == 0 {
			t.Fatal("no signed task", err)
		}
		repeated, err := c.Poll(t.Context(), digest)
		if err != nil || !bytes.Equal(envelope, repeated) {
			t.Fatal("delivery changed", err)
		}
		data, err := engine.Process(t.Context(), envelope)
		if err != nil {
			t.Fatal(err)
		}
		r, err := protocol.DecodeResult(data)
		if err != nil || r.RequestID != task.RequestID || r.Status != protocol.Succeeded {
			t.Fatal(r, err)
		}
		ack, err := c.SubmitResult(t.Context(), data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.SubmitResult(t.Context(), data); err != nil {
			t.Fatal("lost acknowledgment retry failed", err)
		}
		if err := worker.Acknowledge(t.Context(), ack.RequestID, ack.ResultDigest); err != nil {
			t.Fatal(err)
		}
		worker.Close()
		worker = nil
		worker, err = probe.Open(dir, f.node, pub)
		if err != nil {
			t.Fatal(err)
		}
		engine = probe.NewEngine(worker, path, s.URL)
		cached, err := engine.Process(t.Context(), envelope)
		if err != nil || !bytes.Equal(data, cached) {
			t.Fatal("restart did not preserve result", err)
		}
	}
	// Queue under the previous policy, then change local authority before receipt.
	if _, err := f.store.Enqueue(t.Context(), f.node.AgentID, protocol.SystemInfo, "operator", time.Minute); err != nil {
		t.Fatal(err)
	}
	p.Paused = true
	policyBytes, _ = json.Marshal(p)
	if err := os.WriteFile(path, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	envelope, err := c.Poll(t.Context(), digest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := engine.Process(t.Context(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.DecodeResult(data)
	if err != nil || r.ErrorCode != "policy_mismatch" {
		t.Fatal(r, err)
	}
	if _, err := c.SubmitResult(t.Context(), data); err != nil {
		t.Fatal("local rejection not accepted", err)
	}
	rows, err := f.store.Tasks(t.Context(), 0, 100)
	if err != nil || len(rows) != 3 || rows[2].State != "rejected" {
		t.Fatal(rows, err)
	}
	for _, read := range []func() (audit.Page, error){func() (audit.Page, error) { return f.store.Audit(t.Context(), 0, 100) }, func() (audit.Page, error) { return probe.ReadAudit(t.Context(), dir, 0, 100) }} {
		page, err := read()
		if err != nil || page.HeadSequence < 5 || page.HeadHash == "" {
			t.Fatal("missing durable audit", err)
		}
	}
	// Framing is strict before polling touches task state.
	raw := rawClient(t, f.clientTLS)
	for _, body := range []string{`{"version":1,"policy_digest":"` + digest + `","command":"id"}`, strings.Repeat(" ", 257), `{"version":1,"version":1,"policy_digest":"` + digest + `"}`} {
		resp, err := raw.Post(s.URL+server.PollPath, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatal("invalid poll accepted", resp.StatusCode)
		}
	}
	if err := f.store.Disable(t.Context(), f.node.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Poll(t.Context(), digest); err == nil {
		t.Fatal("disabled node polled on existing connection")
	}
}
