package state

import (
	"errors"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
)

func TestRestoreQuarantineIsAtomicAndDurable(t *testing.T) {
	s, dir, bundle, key := taskStore(t)
	account(t, s, "operator", adminauth.Admin)
	session := login(t, s, "operator")
	token := issue(t, s)
	dispatched := enqueue(t, s, bundle.Node.AgentID)
	if _, err := s.Poll(t.Context(), bundle.Probe.Leaf, dispatched.PolicyDigest, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	enqueue(t, s, bundle.Node.AgentID)
	if _, err := s.db.Exec("CREATE TRIGGER fail_recovery BEFORE INSERT ON audit_events WHEN NEW.kind='restore_quarantined' BEGIN SELECT RAISE(ABORT,'disk failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineRestore(t.Context()); err == nil {
		t.Fatal("unaudited recovery succeeded")
	}
	if _, err := s.Authorize(bundle.Probe.Leaf); err != nil {
		t.Fatal("failed transaction disabled node", err)
	}
	if err := me(t, s, session.Token); err != nil {
		t.Fatal("failed transaction revoked session", err)
	}
	var consumed bool
	hash, _ := tokenHash(token)
	if err := s.db.QueryRow("SELECT consumed FROM enrollment_tokens WHERE token_hash=?", hash).Scan(&consumed); err != nil || consumed {
		t.Fatal("failed transaction consumed token", err)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_recovery"); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineRestore(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Authorize(bundle.Probe.Leaf); err == nil {
		t.Fatal("old node identity survived recovery")
	}
	if err := me(t, s, session.Token); !errors.Is(err, ErrAdminUnauthorized) {
		t.Fatal("old session survived recovery", err)
	}
	if err := s.Register(t.Context(), token, registration()); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old enrollment token survived recovery", err)
	}
	rows, err := s.Tasks(t.Context(), 0, 10)
	if err != nil || len(rows) != 2 || rows[0].State != "indeterminate" || rows[1].State != "rejected" {
		t.Fatal("task evidence lost or still dispatchable", err)
	}
	var reserved int
	if err := s.db.QueryRow("SELECT reserved FROM audit_head WHERE id=1").Scan(&reserved); err != nil || reserved != 0 {
		t.Fatal("recovery leaked audit reservations", err)
	}
	if err := me(t, s, login(t, s, "operator").Token); err != nil {
		t.Fatal("local account cannot log in after review", err)
	}
}
