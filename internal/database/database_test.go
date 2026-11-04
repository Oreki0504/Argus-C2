package database

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func fixture(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "db"), true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	_, e = s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('node','host','fp','active',1,9999999999,'cert')")
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestAuditFailureRollsBackTaskAndDisable(t *testing.T) {
	s := fixture(t)
	if _, e := s.DB.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'injected audit failure'); END`); e != nil {
		t.Fatal(e)
	}
	_, e := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 10000})
	if e == nil {
		t.Fatal("audit failure hidden")
	}
	var count int
	if e = s.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&count); e != nil || count != 0 {
		t.Fatal("task survived failed transaction", e)
	}
	if e = s.Disable(t.Context(), "admin", "node"); e == nil {
		t.Fatal("disable ignored audit failure")
	}
	var status string
	if e = s.DB.QueryRow("SELECT status FROM nodes WHERE id='node'").Scan(&status); e != nil || status != "active" {
		t.Fatal("disable partially committed", e)
	}
}
func TestExpiryDistinguishesUndeliveredAndUncertain(t *testing.T) {
	s := fixture(t)
	for _, status := range []protocol.TaskStatus{protocol.Pending, protocol.Accepted, protocol.Running} {
		job, e := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 10000})
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().Unix()
		if _, e = s.DB.Exec("UPDATE tasks SET status=?,created_at=?,dispatch_expires_at=?,result_due_at=? WHERE id=?", status, now-200, now-100, now-40, job.ID); e != nil {
			t.Fatal(e)
		}
		view, e := s.Task(t.Context(), job.ID)
		if e != nil {
			t.Fatal(e)
		}
		if status == protocol.Pending {
			if view.Task.Status != protocol.Failed || view.Result == nil || view.Result.Error != "expired_before_dispatch" {
				t.Fatal(view)
			}
		} else if view.Task.Status != protocol.Unknown || view.Result != nil {
			t.Fatal("fabricated execution outcome", view)
		}
	}
}
func TestAuditRetentionAndLegacyRejection(t *testing.T) {
	s := fixture(t)
	e := s.Write(t.Context(), func(tx *sql.Tx) error {
		if _, e := tx.Exec("INSERT INTO audit_events(id,timestamp,actor,action,node_id,task_id,status) VALUES(1,1,'a','old','','','ok'),(100001,1,'a','recent','','','ok')"); e != nil {
			return e
		}
		return Audit(t.Context(), tx, "admin", "retention", "", "", "succeeded")
	})
	if e != nil {
		t.Fatal(e)
	}
	var n int
	if e = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE id=1").Scan(&n); e != nil || n != 0 {
		t.Fatal("retention did not prune", e)
	}
	dir := filepath.Join(t.TempDir(), "legacy")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	db, e := Open(dir, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.DB.Exec("PRAGMA user_version=8"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if db, e = Open(dir, true); e == nil {
		db.Close()
		t.Fatal("legacy schema accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e = s.Write(ctx, func(*sql.Tx) error { return errors.New("must not execute") }); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestDispatchAndResultClockBoundaries(t *testing.T) {
	s := fixture(t)
	now := time.Now().Truncate(time.Second)
	s.clock = func() time.Time { return now }
	cert := &x509.Certificate{Raw: []byte("test-certificate"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI("node")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, e := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=? WHERE id='node'", identity.Fingerprint(cert)); e != nil {
		t.Fatal(e)
	}
	job, e := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 1001})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Poll(t.Context(), cert); e != nil {
		t.Fatal(e)
	}
	now = now.Add(59 * time.Second)
	if e = s.Running(t.Context(), cert, job.ID); e != nil {
		t.Fatal(e)
	}
	v, e := s.Task(t.Context(), job.ID)
	if e != nil {
		t.Fatal(e)
	}
	due := v.Task.ResultDueAt
	if due != now.Unix()+2+protocol.ResultGraceSeconds {
		t.Fatal("incorrect rounded due time", due)
	}
	now = now.Add(time.Second)
	if e = s.Running(t.Context(), cert, job.ID); e != nil {
		t.Fatal("repeat grant rejected", e)
	}
	v, e = s.Task(t.Context(), job.ID)
	if e != nil || v.Task.ResultDueAt != due || v.Task.Status != protocol.Running {
		t.Fatal(v, e)
	}
	now = time.Unix(due, 0)
	v, e = s.Task(t.Context(), job.ID)
	if e != nil || v.Task.Status != protocol.Unknown || v.Result != nil {
		t.Fatal(v, e)
	}
	if e = s.Running(t.Context(), cert, job.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("overdue work authorized", e)
	}
	result := protocol.NewResult(job, protocol.Failed, "timeout")
	if e = s.SubmitResult(t.Context(), cert, result); e != nil {
		t.Fatal(e)
	}
	now = now.Add(24 * time.Hour)
	if e = s.SubmitResult(t.Context(), cert, result); e != nil {
		t.Fatal("late duplicate rejected", e)
	}
}

func TestBackupPrivateVerifiedAndNeverOverwritten(t *testing.T) {
	s := fixture(t)
	path := filepath.Join(t.TempDir(), "backup.db")
	if e := s.Backup(t.Context(), path); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("backup not private")
	}
	if e = s.Backup(t.Context(), path); e == nil {
		t.Fatal("existing backup overwritten")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("existing backup changed", e)
	}
}

func TestIgnoredTransitionRollsBackResultAndAudit(t *testing.T) {
	s := fixture(t)
	now := time.Now()
	cert := &x509.Certificate{Raw: []byte("transition-cert"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI("node")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, err := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=? WHERE id='node'", identity.Fingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	job, err := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Poll(t.Context(), cert); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`CREATE TRIGGER ignore_transition BEFORE UPDATE OF status ON tasks BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.Running(t.Context(), cert, job.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("ignored transition reported as authorized", err)
	}
	if err = s.SubmitResult(t.Context(), cert, protocol.NewResult(job, protocol.Failed, "denied")); !errors.Is(err, ErrConflict) {
		t.Fatal("ignored transition committed result", err)
	}
	view, err := s.Task(t.Context(), job.ID)
	if err != nil || view.Result != nil || view.Task.Status != protocol.Accepted {
		t.Fatal("partial result commit", view, err)
	}
	var n int
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE task_id=? AND action IN ('task.run','task.complete')", job.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("audit records an ignored transition", n, err)
	}
}
