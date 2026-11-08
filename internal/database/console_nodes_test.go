package database

import (
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestDeleteNodeRevokesIdentityAndKeepsAuditAtomically(t *testing.T) {
	s := fixture(t)
	ctx := t.Context()
	c := &x509.Certificate{Raw: []byte("node-cert"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI("node")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	if _, err := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=? WHERE id='node'", identity.Fingerprint(c)); err != nil {
		t.Fatal(err)
	}
	job, err := s.CreateTask(ctx, "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Poll(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err = s.SubmitResult(ctx, c, protocol.NewResult(job, protocol.Failed, "policy_denied")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("INSERT INTO enrollment_tokens(digest,expires_at,node_id) VALUES('old-token',9999999999,'node')"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`CREATE TRIGGER reject_delete_audit BEFORE INSERT ON audit_events WHEN NEW.action='node.delete' BEGIN SELECT RAISE(FAIL,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteConsoleNode(ctx, "admin", "node"); err == nil {
		t.Fatal("ignored audit failure")
	}
	if _, err = s.Task(ctx, job.ID); err != nil {
		t.Fatal("partial deletion", err)
	}
	if _, err = s.DB.Exec("DROP TRIGGER reject_delete_audit"); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteConsoleNode(ctx, "admin", "node"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"nodes", "tasks", "results", "console_nodes", "enrollment_tokens"} {
		var n int
		if err = s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal(table, n, err)
		}
	}
	if _, err = s.Poll(ctx, c); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old identity accepted", err)
	}
	var n int
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='node.delete' AND node_id='node'").Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

func TestPublicNodeNameValidation(t *testing.T) {
	for _, name := range []string{"", " leading", "trailing ", "line\nbreak", "hidden\u202e", string([]byte{255})} {
		if ValidNodeName(name) {
			t.Fatal("invalid name accepted", name)
		}
	}
	s := fixture(t)
	if err := s.RenameConsoleNode(t.Context(), "admin", "node", "东京 · Web 01"); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := s.DB.QueryRow("SELECT display_name FROM console_nodes WHERE node_id='node'").Scan(&name); err != nil || name != "东京 · Web 01" {
		t.Fatal(name, err)
	}
}
