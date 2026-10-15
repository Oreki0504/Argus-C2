package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func TestSignerRotationOverMTLSPreservesPendingResults(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	oldPub, old, _ := ed25519.GenerateKey(rand.Reader)
	newPub, next, _ := ed25519.GenerateKey(rand.Reader)
	service, err := server.NewTaskService(t.Context(), f.store, old)
	if err != nil {
		t.Fatal(err)
	}
	oldURL := renewalServer(t, f, nil, service)
	c, err := agent.NewClient(oldURL, f.clientTLS, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b, err := os.ReadFile("../../examples/task-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "policy.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	replay := filepath.Join(f.root, "replay")
	if err := probe.Initialize(replay, f.node, oldPub); err != nil {
		t.Fatal(err)
	}
	worker, err := probe.Open(replay, f.node, oldPub)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if worker != nil {
			worker.Close()
		}
	}()
	h := collectHeartbeat(t, f.node)
	h.Version = 2
	h.PolicyDigest, _ = p.Digest()
	h.TaskState = "ready"
	if err := c.Heartbeat(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	first, err := f.store.Enqueue(t.Context(), f.node.AgentID, protocol.SystemInfo, "operator", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := c.Poll(t.Context(), h.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.NewEngine(worker, path, oldURL).Process(t.Context(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	worker = nil
	now := time.Now()
	trust, err := signing.Stage(oldPub, nil, newPub, now, now.Add(time.Hour).Unix(), now.Add(24*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.PauseDispatch(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := probe.MigrateTrust(t.Context(), replay, f.node, oldPub, nil, trust); err != nil {
		t.Fatal(err)
	}
	if err := f.store.InstallSignerTrust(t.Context(), signing.KeyID(oldPub), trust); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SwitchSigner(t.Context(), signing.KeyID(newPub)); err != nil {
		t.Fatal(err)
	}
	service2, err := server.NewTaskService(t.Context(), f.store, next)
	if err != nil {
		t.Fatal(err)
	}
	url := renewalServer(t, f, nil, service2)
	c2, err := agent.NewClient(url, f.clientTLS, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	worker, err = probe.OpenWithTrust(replay, f.node, trust)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.PauseDispatch(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Poll(t.Context(), h.PolicyDigest); err == nil {
		t.Fatal("old server process dispatched after switch")
	}
	again, err := c2.Poll(t.Context(), h.PolicyDigest)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("old envelope rewritten", err)
	}
	cached, err := probe.NewEngine(worker, path, url).Process(t.Context(), again)
	if err != nil || !bytes.Equal(result, cached) {
		t.Fatal("replay lost after migration", err)
	}
	pending, err := worker.Pending(t.Context())
	if err != nil || !bytes.Equal(result, pending) {
		t.Fatal("pending result changed", err)
	}
	ack, err := c2.SubmitResult(t.Context(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Acknowledge(t.Context(), ack.RequestID, ack.ResultDigest); err != nil {
		t.Fatal(err)
	}
	second, err := f.store.Enqueue(t.Context(), f.node.AgentID, protocol.SystemInfo, "operator", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := c2.Poll(t.Context(), h.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, id, err := signing.VerifyTrusted(v2, trust, time.Now()); err != nil || id != signing.KeyID(newPub) {
		t.Fatal("new signer not used", err)
	}
	secondResult, err := probe.NewEngine(worker, path, url).Process(t.Context(), v2)
	if err != nil {
		t.Fatal(err)
	}
	worker.Close()
	worker = nil
	retired, err := signing.Retire(trust, signing.KeyID(oldPub))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.PauseDispatch(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := probe.MigrateTrust(t.Context(), replay, f.node, nil, &trust, retired); err != nil {
		t.Fatal(err)
	}
	canonical, _ := trust.Canonical()
	if err := f.store.InstallSignerTrust(t.Context(), audit.Digest(canonical), retired); err != nil {
		t.Fatal(err)
	}
	worker, err = probe.OpenWithTrust(replay, f.node, retired)
	if err != nil {
		t.Fatal(err)
	}
	// A stolen old key cannot create a newly admitted request after retirement.
	forged := second
	forged.RequestID = first.RequestID
	forged.ActorID = "changed"
	payload, _ := json.Marshal(forged)
	oldWire, _ := signing.Sign(payload, old)
	if _, err := probe.NewEngine(worker, path, url).Process(t.Context(), oldWire); err == nil {
		t.Fatal("retired signer admitted")
	}
	pending, err = worker.Pending(t.Context())
	if err != nil || !bytes.Equal(secondResult, pending) {
		t.Fatal("retirement lost pending result", err)
	}
	if _, err := c2.SubmitResult(t.Context(), pending); err != nil {
		t.Fatal("late result rejected during maintenance", err)
	}
	if err := f.store.PauseDispatch(t.Context(), false); err != nil {
		t.Fatal(err)
	}
}
