// Package probe gates task execution on durable local policy and replay state.
package probe

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const MaxRecords = 8192

var ErrClock = errors.New("task state blocked by clock rollback; explicit recovery is required")
var ErrBusy = errors.New("a task is already running")
var ErrConflict = errors.New("request ID reused with different signed bytes")
var ErrCapacity = errors.New("local replay or result capacity exhausted")

type State struct {
	db   *sql.DB
	lock *os.File
	node identity.Node
	key  ed25519.PublicKey
}

// Initialize is a separate local action. Open never initializes lost state.
func Initialize(dir string, node identity.Node, key ed25519.PublicKey) error {
	if node.Validate() != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("valid node and task key are required")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	db, err := localdb.Open(dir, "probe.db", true)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `CREATE TABLE probe_meta(id INTEGER PRIMARY KEY CHECK(id=1),agent_id TEXT NOT NULL,epoch TEXT NOT NULL,key_digest TEXT NOT NULL,clock_high INTEGER NOT NULL,clock_blocked INTEGER NOT NULL DEFAULT 0,policy_digest TEXT NOT NULL DEFAULT '');
CREATE TABLE executions(request_id TEXT NOT NULL,epoch TEXT NOT NULL,payload BLOB NOT NULL,payload_digest TEXT NOT NULL,policy_digest TEXT NOT NULL,state TEXT NOT NULL,started_at INTEGER NOT NULL,accepted_ms INTEGER NOT NULL,executed INTEGER NOT NULL,expires_at INTEGER NOT NULL,result BLOB,result_digest TEXT NOT NULL DEFAULT '',delivered INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(epoch,request_id));
CREATE INDEX executions_outbox ON executions(delivered,state,accepted_ms);
PRAGMA user_version=1;`)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO probe_meta(id,agent_id,epoch,key_digest,clock_high) VALUES(1,?,?,?,?)", node.AgentID, node.EnrollmentEpoch, audit.Digest(key), time.Now().Unix()); err != nil {
		return err
	}
	if err := audit.Initialize(ctx, tx); err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "state_initialized", AgentID: node.AgentID, Epoch: node.EnrollmentEpoch, Source: "local", Status: "succeeded", PayloadDigest: audit.Digest(key)}, 0); err != nil {
		return err
	}
	return tx.Commit()
}

func Open(dir string, node identity.Node, key ed25519.PublicKey) (*State, error) {
	if node.Validate() != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("valid node and task key are required")
	}
	lock, err := localdb.Lock(dir)
	if err != nil {
		return nil, err
	}
	db, err := localdb.Open(dir, "probe.db", false)
	if err != nil {
		lock.Close()
		return nil, err
	}
	s := &State{db: db, lock: lock, node: node, key: append(ed25519.PublicKey{}, key...)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.recover(ctx, time.Now()); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *State) Close() error {
	err := s.db.Close()
	lockErr := s.lock.Close()
	if err != nil {
		return err
	}
	return lockErr
}

func (s *State) recover(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	var id, epoch, key string
	var health string
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		return errors.New("unknown probe schema")
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&health); err != nil || health != "ok" {
		return errors.New("probe database integrity check failed")
	}
	if err := tx.QueryRowContext(ctx, "SELECT agent_id,epoch,key_digest FROM probe_meta WHERE id=1").Scan(&id, &epoch, &key); err != nil {
		return err
	}
	if id != s.node.AgentID || epoch != s.node.EnrollmentEpoch || key != audit.Digest(s.key) {
		return errors.New("probe state belongs to a different identity or task key")
	}
	if err := audit.Verify(ctx, tx); err != nil {
		return err
	}
	blocked, err := s.clock(ctx, tx, now)
	if err != nil {
		return err
	}
	if blocked {
		if err := tx.Commit(); err != nil {
			return err
		}
		return ErrClock
	}
	rows, err := tx.QueryContext(ctx, "SELECT payload,payload_digest,policy_digest,started_at FROM executions WHERE state='running'")
	if err != nil {
		return err
	}
	type item struct {
		payload      []byte
		hash, digest string
		started      int64
	}
	var items []item
	for rows.Next() {
		var i item
		if err := rows.Scan(&i.payload, &i.hash, &i.digest, &i.started); err != nil {
			rows.Close()
			return err
		}
		items = append(items, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var reserved int
	if err := tx.QueryRowContext(ctx, "SELECT reserved FROM audit_head WHERE id=1").Scan(&reserved); err != nil {
		return err
	}
	if reserved != len(items) || len(items) > 1 {
		return errors.New("inconsistent execution reservations")
	}
	for _, i := range items {
		t, err := protocol.DecodeTask(i.payload)
		if err != nil || audit.Digest(i.payload) != i.hash {
			return errors.New("corrupt interrupted execution")
		}
		r := emptyResult(t, i.digest, i.started, max(i.started, now.Unix()), protocol.Indeterminate, "recovered_after_restart")
		if err := finishTx(ctx, tx, t, r, "local", "task_recovered"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// A rollback is latched in persistent state; restoring the wall clock does not
// silently re-enable execution. Audit capacity is reserved for running tasks.
func (s *State) clock(ctx context.Context, tx *sql.Tx, now time.Time) (bool, error) {
	var high int64
	var blocked bool
	if err := tx.QueryRowContext(ctx, "SELECT clock_high,clock_blocked FROM probe_meta WHERE id=1").Scan(&high, &blocked); err != nil {
		return false, err
	}
	if high <= 0 || now.Unix() <= 0 {
		return false, errors.New("invalid persisted clock state")
	}
	if blocked {
		return true, nil
	}
	if now.Unix() < high-protocol.MaxClockSkew {
		if _, err := tx.ExecContext(ctx, "UPDATE probe_meta SET clock_blocked=1 WHERE id=1"); err != nil {
			return false, err
		}
		// Even a full audit store must not prevent the clock lock from latching.
		var used int64
		if err := tx.QueryRowContext(ctx, "SELECT sequence+reserved FROM audit_head WHERE id=1").Scan(&used); err != nil {
			return false, err
		}
		if used < audit.Capacity {
			if err := audit.Append(ctx, tx, audit.Event{Kind: "clock_rollback", AgentID: s.node.AgentID, Epoch: s.node.EnrollmentEpoch, Source: "local", Status: "blocked"}, 0); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	if now.Unix() > high {
		_, err := tx.ExecContext(ctx, "UPDATE probe_meta SET clock_high=? WHERE id=1", now.Unix())
		return false, err
	}
	return false, nil
}

func (s *State) policy(ctx context.Context, tx *sql.Tx, digest string) error {
	var old string
	if err := tx.QueryRowContext(ctx, "SELECT policy_digest FROM probe_meta WHERE id=1").Scan(&old); err != nil {
		return err
	}
	if old == digest {
		return nil
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "policy_changed", AgentID: s.node.AgentID, Epoch: s.node.EnrollmentEpoch, Source: "local", Status: "succeeded", PolicyDigest: digest}, 0); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE probe_meta SET policy_digest=? WHERE id=1", digest)
	return err
}

func capacity(ctx context.Context, tx *sql.Tx, p policy.Policy, now time.Time) error {
	// Acknowledgment alone never discards replay evidence. Indeterminate and
	// undelivered records are not automatically pruned.
	if _, err := tx.ExecContext(ctx, "DELETE FROM executions WHERE delivered=1 AND state NOT IN ('running','indeterminate') AND expires_at<?", now.Unix()-86400); err != nil {
		return err
	}
	var count, pending int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN delivered=0 THEN LENGTH(result) ELSE 0 END),0) FROM executions").Scan(&count, &pending); err != nil {
		return err
	}
	if count >= MaxRecords || pending+p.MaxResultBytes > p.PendingBytes {
		return ErrCapacity
	}
	var used int64
	if err := tx.QueryRowContext(ctx, "SELECT sequence+reserved FROM audit_head WHERE id=1").Scan(&used); err != nil {
		return err
	}
	if used+2 > audit.Capacity {
		return audit.ErrCapacity
	}
	return nil
}

func (s *State) Ready(ctx context.Context, p policy.Policy, now time.Time) error {
	digest, err := p.Digest()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	blocked, err := s.clock(ctx, tx, now)
	if err != nil {
		return err
	}
	if blocked {
		if err := tx.Commit(); err != nil {
			return err
		}
		return ErrClock
	}
	if err := s.policy(ctx, tx, digest); err != nil {
		return err
	}
	if err := capacity(ctx, tx, p, now); err != nil {
		return err
	}
	var running int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM executions WHERE state='running'").Scan(&running); err != nil {
		return err
	}
	if running > 0 {
		return ErrBusy
	}
	return tx.Commit()
}

type decision struct {
	run     bool
	result  []byte
	digest  string
	started int64
}

func emptyResult(t protocol.Task, digest string, start, end int64, status protocol.TaskStatus, code protocol.ErrorCode) protocol.Result {
	return protocol.Result{RequestID: t.RequestID, AgentID: t.AgentID, Epoch: t.EnrollmentEpoch, Type: t.Type, StartedAt: start, FinishedAt: end, Status: status, Data: json.RawMessage(`{}`), ErrorCode: code, PolicyDigest: digest}
}

func (s *State) prepare(ctx context.Context, t protocol.Task, payload []byte, p policy.Policy, source string, now time.Time) (decision, error) {
	digest, err := p.Digest()
	if err != nil {
		return decision{}, err
	}
	if t.AgentID != s.node.AgentID || t.EnrollmentEpoch != s.node.EnrollmentEpoch {
		return decision{}, errors.New("wrong task identity")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return decision{}, err
	}
	defer tx.Rollback()
	blocked, err := s.clock(ctx, tx, now)
	if err != nil {
		return decision{}, err
	}
	if blocked {
		if err := tx.Commit(); err != nil {
			return decision{}, err
		}
		return decision{}, ErrClock
	}
	hash := audit.Digest(payload)
	var previous, resultHash string
	var result []byte
	err = tx.QueryRowContext(ctx, "SELECT payload_digest,result,result_digest FROM executions WHERE epoch=? AND request_id=?", t.EnrollmentEpoch, t.RequestID).Scan(&previous, &result, &resultHash)
	if err == nil {
		if previous != hash {
			if err := audit.Append(ctx, tx, audit.TaskEvent("task_conflict", t, source, "rejected", "request_conflict", hash), 0); err != nil {
				return decision{}, err
			}
			if err := tx.Commit(); err != nil {
				return decision{}, err
			}
			return decision{}, ErrConflict
		}
		if len(result) == 0 {
			return decision{}, ErrBusy
		}
		cached, err := protocol.DecodeResult(result)
		if err != nil || audit.Digest(result) != resultHash || cached.RequestID != t.RequestID || cached.AgentID != t.AgentID || cached.Epoch != t.EnrollmentEpoch || cached.Type != t.Type {
			return decision{}, errors.New("cached result is corrupt")
		}
		return decision{result: result}, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return decision{}, err
	}
	if err := s.policy(ctx, tx, digest); err != nil {
		return decision{}, err
	}
	if err := capacity(ctx, tx, p, now); err != nil {
		return decision{}, err
	}
	var running, minute, burst int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM executions WHERE state='running'").Scan(&running); err != nil {
		return decision{}, err
	}
	if running > 0 {
		return decision{}, ErrBusy
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM executions WHERE executed=1 AND accepted_ms>?", now.Add(-time.Minute).UnixMilli()).Scan(&minute); err != nil {
		return decision{}, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM executions WHERE executed=1 AND accepted_ms>?", now.Add(-time.Second).UnixMilli()).Scan(&burst); err != nil {
		return decision{}, err
	}
	status := protocol.Running
	var code protocol.ErrorCode
	switch {
	case now.Unix() >= t.ExpiresAt:
		status = protocol.Expired
		code = "expired"
	case now.Unix() < t.CreatedAt-protocol.MaxClockSkew:
		status = protocol.Rejected
		code = "future"
	case t.PolicyDigest != digest:
		status = protocol.Rejected
		code = "policy_mismatch"
	case p.Paused:
		status = protocol.Rejected
		code = "paused"
	case !p.Allows(t.Type):
		status = protocol.Rejected
		code = "task_disabled"
	case !p.AllowsResource(t):
		status = protocol.Rejected
		code = "resource_denied"
	case minute >= p.MaxPerMinute || burst >= p.Burst:
		status = protocol.Rejected
		code = "rate_limited"
	}
	execute := status == protocol.Running
	if _, err := tx.ExecContext(ctx, "INSERT INTO executions(request_id,epoch,payload,payload_digest,policy_digest,state,started_at,accepted_ms,executed,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)", t.RequestID, t.EnrollmentEpoch, payload, hash, digest, status, now.Unix(), now.UnixMilli(), execute, t.ExpiresAt); err != nil {
		return decision{}, err
	}
	event := audit.TaskEvent("task_accepted", t, source, string(status), string(code), hash)
	event.PolicyDigest = digest
	if execute {
		if err := audit.Append(ctx, tx, event, 1); err != nil {
			return decision{}, err
		}
	} else {
		event.Kind = "task_rejected"
		r := emptyResult(t, digest, now.Unix(), now.Unix(), status, code)
		result, err = json.Marshal(r)
		if err != nil {
			return decision{}, err
		}
		event.ResultDigest = audit.Digest(result)
		if err := audit.Append(ctx, tx, event, 0); err != nil {
			return decision{}, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE executions SET result=?,result_digest=? WHERE epoch=? AND request_id=?", result, audit.Digest(result), t.EnrollmentEpoch, t.RequestID); err != nil {
			return decision{}, err
		}
	}
	return decision{run: execute, result: result, digest: digest, started: now.Unix()}, tx.Commit()
}

func finishTx(ctx context.Context, tx *sql.Tx, t protocol.Task, r protocol.Result, source, kind string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := r.CheckAssignment(t); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, "UPDATE executions SET state=?,result=?,result_digest=? WHERE epoch=? AND request_id=? AND state='running'", r.Status, data, audit.Digest(data), t.EnrollmentEpoch, t.RequestID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("execution state changed before completion")
	}
	var payloadHash string
	if err := tx.QueryRowContext(ctx, "SELECT payload_digest FROM executions WHERE epoch=? AND request_id=?", t.EnrollmentEpoch, t.RequestID).Scan(&payloadHash); err != nil {
		return err
	}
	e := audit.TaskEvent(kind, t, source, string(r.Status), string(r.ErrorCode), payloadHash)
	e.PolicyDigest = r.PolicyDigest
	e.ResultDigest = audit.Digest(data)
	return audit.Append(ctx, tx, e, -1)
}
func (s *State) finish(ctx context.Context, t protocol.Task, r protocol.Result, source string) ([]byte, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := finishTx(ctx, tx, t, r, source, "task_completed"); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
func (s *State) rejectInvalid(ctx context.Context, digest, source string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := audit.Append(ctx, tx, audit.Event{Kind: "invalid_task", AgentID: s.node.AgentID, Epoch: s.node.EnrollmentEpoch, Source: source, Status: "rejected", Code: "invalid_envelope", PayloadDigest: digest}, 0); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *State) Pending(ctx context.Context) ([]byte, error) {
	var data []byte
	var digest string
	err := s.db.QueryRowContext(ctx, "SELECT result,result_digest FROM executions WHERE delivered=0 AND state<>'running' ORDER BY accepted_ms,request_id LIMIT 1").Scan(&data, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := protocol.DecodeResult(data); err != nil || digest != audit.Digest(data) {
		return nil, errors.New("pending result is corrupt")
	}
	return data, nil
}
func (s *State) Acknowledge(ctx context.Context, request, digest string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE executions SET delivered=1 WHERE request_id=? AND epoch=? AND result_digest=? AND state<>'running'", request, s.node.EnrollmentEpoch, digest)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("result acknowledgment mismatch")
	}
	return nil
}
func ReadAudit(ctx context.Context, dir string, after int64, limit int) (audit.Page, error) {
	db, err := localdb.Open(dir, "probe.db", false)
	if err != nil {
		return audit.Page{}, err
	}
	defer db.Close()
	return audit.Read(ctx, db, after, limit)
}
