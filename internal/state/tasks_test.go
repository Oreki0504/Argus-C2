package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func taskStore(t *testing.T) (*Store, string, *devpki.Bundle, ed25519.PrivateKey) {
	t.Helper()
	s, dir := openTest(t)
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register(t.Context(), issue(t, s), b.Registration()); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.ConfigureSigner(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	h := protocol.Heartbeat{Version: 2, AgentID: b.Node.AgentID, EnrollmentEpoch: b.Node.EnrollmentEpoch, SentAt: time.Now().Unix(), Info: protocol.SystemInformation{OS: "test", Architecture: "test"}, Metrics: protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}}, PolicyDigest: strings.Repeat("a", 64), TaskState: "ready"}
	if err := s.SaveHeartbeat(t.Context(), b.Probe.Leaf, h); err != nil {
		t.Fatal(err)
	}
	return s, dir, b, key
}
func enqueue(t *testing.T, s *Store, id string) protocol.Task {
	t.Helper()
	task, err := s.Enqueue(t.Context(), id, protocol.SystemInfo, "operator", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return task
}
func success(task protocol.Task) []byte {
	now := time.Now().Unix()
	data, _ := json.Marshal(protocol.Result{RequestID: task.RequestID, AgentID: task.AgentID, Epoch: task.EnrollmentEpoch, Type: task.Type, StartedAt: now, FinishedAt: now, Status: protocol.Succeeded, Data: json.RawMessage(`{"available":false,"os":"test","architecture":"test","hostname":"","kernel":"","boot_time":0}`), PolicyDigest: task.PolicyDigest})
	return data
}

func TestDispatchPersistenceOwnershipAndIdempotentResult(t *testing.T) {
	s, dir, b, key := taskStore(t)
	task := enqueue(t, s, b.Node.AgentID)
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, success(task), "127.0.0.1"); err == nil {
		t.Fatal("result accepted before dispatch")
	}
	first, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := signing.Verify(first, key.Public().(ed25519.PublicKey))
	if err != nil || verified.RequestID != task.RequestID {
		t.Fatal("wrong task", err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	retry, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "127.0.0.1")
	if err != nil || !bytes.Equal(first, retry) {
		t.Fatal("redelivery changed", err)
	}
	other, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register(t.Context(), issue(t, s), other.Registration()); err != nil {
		t.Fatal(err)
	}
	if envelope, err := s.Poll(t.Context(), other.Probe.Leaf, task.PolicyDigest, key, "127.0.0.1"); err != nil || len(envelope) != 0 {
		t.Fatal("cross-node delivery", err)
	}
	if _, err := s.SubmitResult(t.Context(), other.Probe.Leaf, success(task), "127.0.0.1"); err == nil {
		t.Fatal("cross-node result")
	}
	data := success(task)
	ack, err := s.SubmitResult(t.Context(), b.Probe.Leaf, data, "127.0.0.1")
	if err != nil || ack.ResultDigest != audit.Digest(data) {
		t.Fatal(err)
	}
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, data, "127.0.0.1"); err != nil {
		t.Fatal("lost-ack retry rejected", err)
	}
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, append([]byte(" "), data...), "127.0.0.1"); err == nil {
		t.Fatal("terminal overwrite accepted")
	}
	page, err := s.Audit(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range page.Records {
		if r.Event.Kind == "result_received" {
			count++
			if r.Event.ResultDigest != audit.Digest(data) {
				t.Fatal("audit omitted result digest")
			}
		}
	}
	if count != 1 {
		t.Fatalf("completion events=%d", count)
	}
	_, different, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.ConfigureSigner(t.Context(), different); err == nil {
		t.Fatal("silently replaced signing key")
	}
}

func TestExpiredDispatchAndDisable(t *testing.T) {
	s, _, b, key := taskStore(t)
	queued := enqueue(t, s, b.Node.AgentID)
	// Move a valid queued payload and its indexed expiry into the past.
	queued.CreatedAt -= 120
	queued.ExpiresAt -= 120
	payload, _ := json.Marshal(queued)
	if _, err := s.db.Exec("UPDATE tasks SET payload=?,expires_at=? WHERE request_id=?", payload, queued.ExpiresAt, queued.RequestID); err != nil {
		t.Fatal(err)
	}
	if data, err := s.Poll(t.Context(), b.Probe.Leaf, queued.PolicyDigest, key, "127.0.0.1"); err != nil || len(data) != 0 {
		t.Fatal("delivered expired task", err)
	}
	dispatched := enqueue(t, s, b.Node.AgentID)
	if _, err := s.Poll(t.Context(), b.Probe.Leaf, dispatched.PolicyDigest, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE tasks SET expires_at=? WHERE request_id=?", time.Now().Unix()-1, dispatched.RequestID); err != nil {
		t.Fatal(err)
	}
	if data, err := s.Poll(t.Context(), b.Probe.Leaf, dispatched.PolicyDigest, key, "127.0.0.1"); err != nil || len(data) != 0 {
		t.Fatal("redelivered expired task", err)
	}
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, success(dispatched), "127.0.0.1"); err != nil {
		t.Fatal("late durable result rejected", err)
	}
	live := enqueue(t, s, b.Node.AgentID)
	if _, err := s.Poll(t.Context(), b.Probe.Leaf, live.PolicyDigest, key, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	enqueue(t, s, b.Node.AgentID)
	if err := s.Disable(t.Context(), b.Node.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Poll(t.Context(), b.Probe.Leaf, live.PolicyDigest, key, "127.0.0.1"); err == nil {
		t.Fatal("disabled poll accepted")
	}
	if _, err := s.SubmitResult(t.Context(), b.Probe.Leaf, success(live), "127.0.0.1"); err == nil {
		t.Fatal("disabled result accepted")
	}
	var reserved int
	if err := s.db.QueryRow("SELECT reserved FROM audit_head").Scan(&reserved); err != nil || reserved != 0 {
		t.Fatal("leaked audit reservations", reserved, err)
	}
	rows, err := s.Tasks(t.Context(), 0, 100)
	if err != nil || len(rows) != 4 {
		t.Fatal(err)
	}
	if rows[0].State != "expired" || rows[2].State != "indeterminate" || rows[3].State != "rejected" {
		t.Fatal(rows)
	}
}

func TestQueueAndAuditWriteFailure(t *testing.T) {
	s, _, b, key := taskStore(t)
	if _, err := s.Enqueue(t.Context(), b.Node.AgentID, "shell.exec", "operator", time.Minute); err == nil {
		t.Fatal("queued arbitrary task")
	}
	if _, err := s.db.Exec("CREATE TRIGGER fail_queue BEFORE INSERT ON audit_events WHEN NEW.kind='task_queued' BEGIN SELECT RAISE(ABORT,'full disk'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(t.Context(), b.Node.AgentID, protocol.SystemInfo, "operator", time.Minute); err == nil {
		t.Fatal("unaudited task queued")
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&count); err != nil || count != 0 {
		t.Fatal("queue rollback failed", err)
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_queue"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		enqueue(t, s, b.Node.AgentID)
	}
	if _, err := s.Enqueue(t.Context(), b.Node.AgentID, protocol.SystemInfo, "operator", time.Minute); err == nil {
		t.Fatal("queue limit not enforced")
	}
	if _, err := s.db.Exec("CREATE TRIGGER fail_dispatch BEFORE INSERT ON audit_events WHEN NEW.kind='task_dispatched' BEGIN SELECT RAISE(ABORT,'full disk'); END"); err != nil {
		t.Fatal(err)
	}
	if data, err := s.Poll(t.Context(), b.Probe.Leaf, strings.Repeat("a", 64), key, "127.0.0.1"); err == nil || len(data) != 0 {
		t.Fatal("unaudited envelope delivered")
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM tasks WHERE envelope IS NOT NULL").Scan(&count); err != nil || count != 0 {
		t.Fatal("dispatch rollback failed", err)
	}
}

func TestSchemaOneMigrationPreservesNodes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "legacy")
	db, err := localdb.Open(dir, "argus.db", true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE enrollment_tokens(token_hash TEXT PRIMARY KEY,expires_at INTEGER NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE nodes(agent_id TEXT PRIMARY KEY,enrollment_epoch TEXT NOT NULL,certificate_sha256 TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL,enrolled_at INTEGER NOT NULL,received_at INTEGER NOT NULL DEFAULT 0,heartbeat BLOB);
PRAGMA user_version=1;`)
	if err != nil {
		t.Fatal(err)
	}
	n := identity.New()
	_, err = db.Exec("INSERT INTO nodes(agent_id,enrollment_epoch,certificate_sha256,enabled,enrolled_at) VALUES(?,?,?,1,?)", n.AgentID, n.EnrollmentEpoch, strings.Repeat("a", 64), time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	nodes, err := s.Snapshots(t.Context())
	if err != nil || len(nodes) != 1 || nodes[0].AgentID != n.AgentID {
		t.Fatal("migration lost node", err)
	}
	if err := s.Disable(t.Context(), n.AgentID); err != nil {
		t.Fatal("migration lost disable audit reservation", err)
	}
}
