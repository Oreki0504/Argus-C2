package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func signerTrust(t *testing.T, key ed25519.PrivateKey) (signing.TrustSet, ed25519.PrivateKey) {
	t.Helper()
	pub, next, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	trust, err := signing.Stage(key.Public().(ed25519.PublicKey), nil, pub, now, now.Add(time.Hour).Unix(), now.Add(48*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	return trust, next
}

func TestExpiredOldAssignmentKeepsLateResultSlotAfterRetirement(t *testing.T) {
	s, _, b, key := taskStore(t)
	task, err := s.Enqueue(t.Context(), b.Node.AgentID, "system.info", "operator", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "local")
	if err != nil {
		t.Fatal(err)
	}
	late := success(task)
	trust, next := signerTrust(t, key)
	if err := s.PauseDispatch(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := s.InstallSignerTrust(t.Context(), signing.KeyID(key.Public().(ed25519.PublicKey)), trust); err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchSigner(t.Context(), signing.KeyID(next.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(time.Unix(task.ExpiresAt, 0)) + time.Millisecond)
	retired, err := signing.Retire(trust, signing.KeyID(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := trust.Canonical()
	if err := s.InstallSignerTrust(t.Context(), audit.Digest(binding), retired); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	s.db.QueryRow("SELECT envelope FROM tasks WHERE request_id=?", task.RequestID).Scan(&stored)
	if !bytes.Equal(stored, wire) {
		t.Fatal("expired assignment overwritten")
	}
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, late, "local"); err != nil {
		t.Fatal("late result lost reserved slot", err)
	}
}

func TestDispatchPauseSerializesAcrossConnections(t *testing.T) {
	s, dir, b, key := taskStore(t)
	enqueue(t, s, b.Node.AgentID)
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other.Enqueue(t.Context(), b.Node.AgentID, "system.info", "operator", time.Minute)
		}()
	}
	if err := s.PauseDispatch(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := other.Enqueue(t.Context(), b.Node.AgentID, "system.info", "operator", time.Minute); err == nil {
		t.Fatal("enqueue survived committed pause")
	}
	var digest string
	s.db.QueryRow("SELECT policy_digest FROM nodes WHERE agent_id=?", b.Node.AgentID).Scan(&digest)
	if wire, err := other.Poll(t.Context(), b.Probe.Leaf, digest, key, "local"); err != nil || len(wire) != 0 {
		t.Fatal("poll survived committed pause", err)
	}
	s.db.Exec("CREATE TRIGGER fail_cancel BEFORE INSERT ON audit_events WHEN NEW.kind='task_cancelled' BEGIN SELECT RAISE(ABORT,'disk full'); END")
	var before int
	s.db.QueryRow("SELECT COUNT(*) FROM tasks WHERE state='queued'").Scan(&before)
	if before > 0 {
		if err := s.CancelQueuedForSignerChange(t.Context()); err == nil {
			t.Fatal("cancellation ignored audit failure")
		}
		var after int
		s.db.QueryRow("SELECT COUNT(*) FROM tasks WHERE state='queued'").Scan(&after)
		if after != before {
			t.Fatal("partial queue cancellation")
		}
	}
}

func TestSignerSwitchPreservesOldEnvelopesAndLateResults(t *testing.T) {
	s, dir, b, key := taskStore(t)
	old := enqueue(t, s, b.Node.AgentID)
	wire, err := s.Poll(t.Context(), b.Probe.Leaf, old.PolicyDigest, key, "local")
	if err != nil {
		t.Fatal(err)
	}
	queued := enqueue(t, s, b.Node.AgentID)
	trust, next := signerTrust(t, key)
	oldID := signing.KeyID(key.Public().(ed25519.PublicKey))
	newID := signing.KeyID(next.Public().(ed25519.PublicKey))
	if err := s.InstallSignerTrust(t.Context(), oldID, trust); err == nil {
		t.Fatal("changed trust without pause")
	}
	if err := s.PauseDispatch(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(t.Context(), b.Node.AgentID, old.Type, "operator", time.Minute); err == nil {
		t.Fatal("enqueue while paused")
	}
	if data, err := s.Poll(t.Context(), b.Probe.Leaf, old.PolicyDigest, key, "local"); err != nil || len(data) != 0 {
		t.Fatal("poll while paused", err)
	}
	if err := s.InstallSignerTrust(t.Context(), oldID, trust); err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchSigner(t.Context(), newID); err == nil {
		t.Fatal("silently retargeted old queued tasks to a new signing key")
	}
	if err := s.CancelQueuedForSignerChange(t.Context()); err != nil {
		t.Fatal(err)
	}
	var state, code string
	if err := s.db.QueryRow("SELECT state,code FROM tasks WHERE request_id=?", queued.RequestID).Scan(&state, &code); err != nil || state != "rejected" || code != "signer_changed_before_dispatch" {
		t.Fatal("queued work was not explicitly terminalized", err)
	}
	if err := s.SwitchSigner(t.Context(), newID); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureSigner(t.Context(), key); err == nil {
		t.Fatal("old server configuration still accepted")
	}
	if err := s.ConfigureSigner(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if err := s.PauseDispatch(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Poll(t.Context(), b.Probe.Leaf, old.PolicyDigest, key, "local"); err == nil {
		t.Fatal("old process continued signing")
	}
	again, err := s.Poll(t.Context(), b.Probe.Leaf, old.PolicyDigest, next, "local")
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("old envelope was re-signed", err)
	}
	retired, err := signing.Retire(trust, oldID)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := trust.Canonical()
	if err := s.PauseDispatch(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := s.InstallSignerTrust(t.Context(), audit.Digest(canonical), retired); err == nil {
		t.Fatal("retired key with live dispatched work")
	}
	// Results remain admissible while dispatch is paused.
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, success(old), "local"); err != nil {
		t.Fatal(err)
	}
	if err := s.InstallSignerTrust(t.Context(), audit.Digest(canonical), retired); err != nil {
		t.Fatal(err)
	}
	if err := s.PauseDispatch(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	queued = enqueue(t, s, b.Node.AgentID)
	newWire, err := s.Poll(t.Context(), b.Probe.Leaf, queued.PolicyDigest, next, "local")
	if err != nil {
		t.Fatal(err)
	}
	task, _, id, err := signing.VerifyTrusted(newWire, retired, time.Now())
	if err != nil || id != newID || task.RequestID != queued.RequestID {
		t.Fatal("new signer dispatch", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.ConfigureSigner(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	retry, err := s.Poll(t.Context(), b.Probe.Leaf, queued.PolicyDigest, next, "local")
	if err != nil || !bytes.Equal(newWire, retry) {
		t.Fatal("restart changed signed bytes", err)
	}
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, success(queued), "local"); err != nil {
		t.Fatal(err)
	}
}

func TestSignerChangeAuditFailureRollsBackAndRetryIsIdempotent(t *testing.T) {
	s, _, _, key := taskStore(t)
	trust, next := signerTrust(t, key)
	if err := s.PauseDispatch(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	s.db.Exec("CREATE TRIGGER fail_signer BEFORE INSERT ON audit_events WHEN NEW.kind='signer_trust_changed' BEGIN SELECT RAISE(ABORT,'disk full'); END")
	id := signing.KeyID(key.Public().(ed25519.PublicKey))
	if err := s.InstallSignerTrust(t.Context(), id, trust); err == nil {
		t.Fatal("ignored audit failure")
	}
	var raw []byte
	s.db.QueryRow("SELECT trust_json FROM dispatch_settings").Scan(&raw)
	if raw != nil {
		t.Fatal("partial trust committed")
	}
	s.db.Exec("DROP TRIGGER fail_signer")
	if err := s.InstallSignerTrust(t.Context(), id, trust); err != nil {
		t.Fatal(err)
	}
	if err := s.InstallSignerTrust(t.Context(), id, trust); err != nil {
		t.Fatal(err)
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE kind='signer_trust_changed'").Scan(&count)
	if count != 1 {
		t.Fatal("duplicate migration audit")
	}
	s.db.Exec("CREATE TRIGGER fail_switch BEFORE INSERT ON audit_events WHEN NEW.kind='signer_selected' BEGIN SELECT RAISE(ABORT,'disk full'); END")
	if err := s.SwitchSigner(t.Context(), signing.KeyID(next.Public().(ed25519.PublicKey))); err == nil {
		t.Fatal("switch ignored audit failure")
	}
	var selected string
	s.db.QueryRow("SELECT key_digest FROM dispatch_settings").Scan(&selected)
	if selected != id {
		t.Fatal("partially switched signer")
	}
}

func TestSchemaFourMigrationPreservesState(t *testing.T) {
	s, dir, b, key := taskStore(t)
	task := enqueue(t, s, b.Node.AgentID)
	wire, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "local")
	if err != nil {
		t.Fatal(err)
	}
	var seq int
	var hash string
	s.db.QueryRow("SELECT sequence,hash FROM audit_head").Scan(&seq, &hash)
	if _, err := s.db.Exec("ALTER TABLE dispatch_settings DROP COLUMN trust_json; ALTER TABLE dispatch_settings DROP COLUMN paused; PRAGMA user_version=4"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var actual string
	s.db.QueryRow("SELECT hash FROM audit_events WHERE sequence=?", seq).Scan(&actual)
	if actual != hash {
		t.Fatal("migration changed audit history")
	}
	retry, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "local")
	if err != nil || !bytes.Equal(wire, retry) {
		t.Fatal("migration changed dispatch", err)
	}
}
