package database

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func seedHistory(t *testing.T, s *Store, id string, status protocol.TaskStatus, due int64, result bool) {
	t.Helper()
	_, err := s.DB.Exec("INSERT INTO tasks("+taskColumns+") VALUES(?,'node','system.info','{}',?,1,?,1000,?)", id, status, due, due)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		_, err = s.DB.Exec("INSERT INTO results(task_id,node_id,status,payload,error,completed_at,received_at) VALUES(?,'node',?,'{}','',?,?)", id, status, due, due)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func historyCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPrunePreviewBoundariesAndBackupRestore(t *testing.T) {
	s := fixture(t)
	now := time.Now().Truncate(time.Second)
	s.clock = func() time.Time { return now }
	cutoff := now.Add(-30 * 24 * time.Hour).Unix()
	for _, status := range []protocol.TaskStatus{protocol.Succeeded, protocol.Failed, protocol.Unknown} {
		seedHistory(t, s, string(status), status, cutoff-1, true)
	}
	for _, status := range []protocol.TaskStatus{protocol.Pending, protocol.Accepted, protocol.Running, protocol.Unknown} {
		seedHistory(t, s, "keep-"+string(status), status, cutoff-1, false)
	}
	seedHistory(t, s, "boundary", protocol.Succeeded, cutoff, true)
	seedHistory(t, s, "later-receipt", protocol.Succeeded, cutoff-1, true)
	if _, err := s.DB.Exec("UPDATE results SET received_at=? WHERE task_id='later-receipt'", cutoff+1); err != nil {
		t.Fatal(err)
	}
	p, err := s.PreviewPrune(t.Context(), DefaultRetentionDays, 90, 2)
	if err != nil || len(p.Items) != 2 || p.Cutoff != cutoff || p.Applied {
		t.Fatal(p, err)
	}
	if historyCount(t, s, "tasks") != 9 || historyCount(t, s, "results") != 5 || historyCount(t, s, "audit_events") != 0 {
		t.Fatal("preview mutated state")
	}
	dir := filepath.Join(t.TempDir(), "restored")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "argus.db")
	p, err = s.Prune(t.Context(), 30, 90, 1000, backup)
	if err != nil || !p.Applied || p.Deleted != 3 {
		t.Fatal(p, err)
	}
	if historyCount(t, s, "tasks") != 6 || historyCount(t, s, "results") != 2 {
		t.Fatal("incorrect deletion")
	}
	events, err := s.AuditEvents(t.Context(), 0)
	if err != nil || len(events) != 3 {
		t.Fatal(events, err)
	}
	for _, e := range events {
		if e.Action != "task.prune" || e.Actor != "local-operator" || e.NodeID != "node" || e.TaskID == "" {
			t.Fatal(e)
		}
	}
	restored, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if historyCount(t, restored, "tasks") != 9 || historyCount(t, restored, "results") != 5 {
		t.Fatal("backup lost candidates")
	}
	for _, v := range [][2]int{{0, 1}, {36501, 1}, {30, 0}, {30, 1001}} {
		if _, err = s.PreviewPrune(t.Context(), v[0], 90, v[1]); err == nil {
			t.Fatal("invalid bounds accepted", v)
		}
	}
}

func TestPruneBackupAndTransactionFailuresPreserveHistory(t *testing.T) {
	for _, failure := range []string{"backup", "audit", "delete", "ignored-delete"} {
		t.Run(failure, func(t *testing.T) {
			s := fixture(t)
			seedHistory(t, s, "old", protocol.Failed, 1, true)
			backup := filepath.Join(t.TempDir(), "snapshot.db")
			switch failure {
			case "backup":
				if err := os.WriteFile(backup, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			case "audit":
				if _, err := s.DB.Exec("CREATE TRIGGER fail BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'injected'); END"); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if _, err := s.DB.Exec("CREATE TRIGGER fail BEFORE DELETE ON tasks BEGIN SELECT RAISE(FAIL,'injected'); END"); err != nil {
					t.Fatal(err)
				}
			case "ignored-delete":
				if _, err := s.DB.Exec("CREATE TRIGGER fail BEFORE DELETE ON tasks BEGIN SELECT RAISE(IGNORE); END"); err != nil {
					t.Fatal(err)
				}
			}
			p, err := s.Prune(t.Context(), 30, 90, 200, backup)
			if err == nil || p.Applied || p.Deleted != 0 {
				t.Fatal(p, err)
			}
			if historyCount(t, s, "tasks") != 1 || historyCount(t, s, "results") != 1 || historyCount(t, s, "audit_events") != 0 {
				t.Fatal("partial prune committed")
			}
			if failure == "backup" {
				b, _ := os.ReadFile(backup)
				if string(b) != "existing" {
					t.Fatal("backup overwritten")
				}
			}
		})
	}
}

func TestPruneFrozenBatchAndStaleCandidate(t *testing.T) {
	s := fixture(t)
	seedHistory(t, s, "old", protocol.Succeeded, 1, true)
	p, err := s.PreviewPrune(t.Context(), 30, 90, 200)
	if err != nil {
		t.Fatal(err)
	}
	seedHistory(t, s, "late", protocol.Succeeded, 1, true)
	if err = s.Write(t.Context(), func(tx *sql.Tx) error { return pruneBatch(t.Context(), tx, p) }); err != nil {
		t.Fatal(err)
	}
	if historyCount(t, s, "tasks") != 1 {
		t.Fatal("late result joined frozen batch")
	}
	if err = s.Write(t.Context(), func(tx *sql.Tx) error { return pruneBatch(t.Context(), tx, p) }); err == nil {
		t.Fatal("stale batch accepted")
	}
	if historyCount(t, s, "tasks") != 1 || historyCount(t, s, "audit_events") != 1 {
		t.Fatal("stale batch mutated state")
	}
}

func TestStaleSecondCandidateRollsBackEarlierDeletion(t *testing.T) {
	s := fixture(t)
	seedHistory(t, s, "a", protocol.Succeeded, 1, true)
	seedHistory(t, s, "b", protocol.Succeeded, 1, true)
	p, err := s.PreviewPrune(t.Context(), 30, 90, 200)
	if err != nil {
		t.Fatal(err)
	}
	// Concurrent maintenance changed the second candidate after the preview.
	if _, err = s.DB.Exec("DELETE FROM results WHERE task_id='b'"); err != nil {
		t.Fatal(err)
	}
	if err = s.Write(t.Context(), func(tx *sql.Tx) error { return pruneBatch(t.Context(), tx, p) }); err == nil {
		t.Fatal("stale batch committed")
	}
	if historyCount(t, s, "tasks") != 2 || historyCount(t, s, "results") != 1 || historyCount(t, s, "audit_events") != 0 {
		t.Fatal("earlier candidate deletion was not rolled back")
	}
}

func TestPrunedTaskCannotBeGrantedOrAcknowledgeLateResult(t *testing.T) {
	s := fixture(t)
	now := time.Now()
	c := &x509.Certificate{Raw: []byte("retention-test"), URIs: []*url.URL{identity.URI("node")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, err := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=?", identity.Fingerprint(c)); err != nil {
		t.Fatal(err)
	}
	seedHistory(t, s, "old", protocol.Failed, 1, true)
	if _, err := s.Prune(t.Context(), 30, 90, 200, filepath.Join(t.TempDir(), "backup.db")); err != nil {
		t.Fatal(err)
	}
	if err := s.Running(t.Context(), c, "old"); !errors.Is(err, ErrTaskNotFound) {
		t.Fatal(err)
	}
	r := protocol.Result{TaskID: "old", NodeID: "node", Status: protocol.Failed, Payload: []byte(`{}`), Error: "collector_timeout", CompletedAt: now.Unix()}
	if err := s.SubmitResult(t.Context(), c, r); !errors.Is(err, ErrTaskNotFound) {
		t.Fatal("late result falsely acknowledged", err)
	}
	if task, err := s.Poll(t.Context(), c); err != nil || task != nil {
		t.Fatal("pruned task redelivered", task, err)
	}
}
