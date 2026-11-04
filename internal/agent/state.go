package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const SchemaVersion = 101
const applicationID = 0x41524741 // ARGA; independent of the server schema.
const PendingLimit = 1000
const PendingByteLimit = 32 * 1024 * 1024

var ErrCapacity = errors.New("pending result capacity reached")
var ErrResultHeld = errors.New("result requires operator attention")
var ErrResultDiscarded = errors.New("result was discarded locally; task must not execute again")

type State struct {
	db     *sql.DB
	lock   *os.File
	NodeID string
	mu     sync.Mutex
	// Failed writes can have uncertain commit outcomes. Until reconciled, no
	// collection may start. On restart ACCEPTED/RUNNING provide the same barrier.
	interrupted map[string]protocol.Result
}

func OpenState(dir, id string, create bool) (*State, error) {
	db, e := localdb.Open(dir, "probe.db", create)
	if e != nil {
		return nil, e
	}
	lock, e := localdb.Lock(dir)
	if e != nil {
		db.Close()
		return nil, e
	}
	s := &State{db: db, lock: lock, NodeID: id, interrupted: map[string]protocol.Result{}}
	fail := func(e error) (*State, error) { s.Close(); return nil, e }
	var version, count, component int
	if e = db.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		return fail(e)
	}
	if e = db.QueryRow("PRAGMA application_id").Scan(&component); e != nil {
		return fail(e)
	}
	if component != 0 && component != applicationID {
		return fail(errors.New("database belongs to another component"))
	}
	if e = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&count); e != nil {
		return fail(e)
	}
	if version == 0 && count == 0 && component == 0 && create {
		tx, e := db.Begin()
		if e != nil {
			return fail(e)
		}
		_, e = tx.Exec(`CREATE TABLE identity(node_id TEXT PRIMARY KEY);
CREATE TABLE executions(id TEXT PRIMARY KEY,task TEXT NOT NULL,status TEXT NOT NULL,result TEXT NOT NULL DEFAULT '',delivery TEXT NOT NULL DEFAULT 'pending' CHECK(delivery IN ('pending','acknowledged','held','discarded')),delivery_error TEXT NOT NULL DEFAULT '',dispatch_expires_at INTEGER NOT NULL);
PRAGMA user_version=101;PRAGMA application_id=1095911233;INSERT INTO identity VALUES(?)`, id)
		if e != nil {
			tx.Rollback()
			return fail(e)
		}
		if e = tx.Commit(); e != nil {
			return fail(e)
		}
	} else if version != SchemaVersion {
		return fail(errors.New("incompatible or missing agent state; preserve identity and deduplication state"))
	}
	if e = db.QueryRow("PRAGMA application_id").Scan(&component); e != nil {
		return fail(e)
	}
	if component != applicationID {
		return fail(errors.New("database belongs to another component"))
	}
	var actual string
	if e = db.QueryRow("SELECT node_id FROM identity").Scan(&actual); e != nil || actual != id {
		return fail(errors.New("agent state belongs to a different node"))
	}
	rows, e := db.Query("SELECT task FROM executions WHERE status IN ('ACCEPTED','RUNNING')")
	if e != nil {
		return fail(e)
	}
	for rows.Next() {
		var b string
		if e = rows.Scan(&b); e != nil {
			rows.Close()
			return fail(e)
		}
		t, e := protocol.DecodeTask([]byte(b))
		if e != nil {
			rows.Close()
			return fail(e)
		}
		s.interrupted[t.ID] = protocol.NewResult(t, protocol.Unknown, "agent_interrupted")
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return fail(e)
	}
	if e = s.recover(context.Background()); e != nil {
		return fail(e)
	}
	return s, nil
}
func (s *State) Close() error { return errors.Join(s.db.Close(), s.lock.Close()) }

// recover runs under mu (or before OpenState publishes the State).
func (s *State) recover(ctx context.Context) error {
	for id, r := range s.interrupted {
		var stored string
		if e := s.db.QueryRowContext(ctx, "SELECT result FROM executions WHERE id=?", id).Scan(&stored); e != nil {
			return e
		}
		if stored != "" {
			// A failed commit response may still have left a valid, immutable result.
			old, e := protocol.DecodeResult([]byte(stored))
			if e != nil {
				return e
			}
			if old.TaskID != id || old.NodeID != s.NodeID {
				return errors.New("invalid persisted result identity")
			}
		} else if e := s.finish(ctx, r); e != nil {
			return e
		}
		delete(s.interrupted, id)
	}
	return nil
}
func (s *State) Recover(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recover(ctx)
}
func (s *State) interruption(t protocol.Task, code string) {
	if _, ok := s.interrupted[t.ID]; !ok {
		s.interrupted[t.ID] = protocol.NewResult(t, protocol.Unknown, code)
	}
}

// prepare atomically accepts work and reserves one maximum-sized result by
// counting empty pending executions. No separate reservation ledger is needed.
func (s *State) prepare(ctx context.Context, t protocol.Task) (*protocol.Result, error) {
	if e := s.recover(ctx); e != nil {
		return nil, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "DELETE FROM executions WHERE delivery IN ('acknowledged','discarded') AND dispatch_expires_at+86400<?", time.Now().Unix()); e != nil {
		return nil, e
	}
	var old, result, status, delivery string
	e = tx.QueryRowContext(ctx, "SELECT task,result,status,delivery FROM executions WHERE id=?", t.ID).Scan(&old, &result, &status, &delivery)
	if e == nil {
		prev, e := protocol.DecodeTask([]byte(old))
		if e != nil {
			return nil, e
		}
		if !protocol.SameAssignment(prev, t) {
			return nil, errors.New("task ID reused with different assignment")
		}
		if delivery == "discarded" {
			return nil, ErrResultDiscarded
		}
		if delivery == "held" {
			return nil, ErrResultHeld
		}
		if result != "" {
			r, e := protocol.DecodeResult([]byte(result))
			return &r, e
		}
		if status == string(protocol.Running) {
			// A terminal write failed before this redelivery; never rerun collection.
			tx.Rollback()
			s.interruption(t, "result_persistence_interrupted")
			if e = s.recover(ctx); e != nil {
				return nil, e
			}
			return s.prepare(ctx, t)
		}
		if status != string(protocol.Accepted) {
			return nil, errors.New("invalid unfinished execution")
		}
		return nil, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	var bytes, count int64
	if e = tx.QueryRowContext(ctx, `SELECT coalesce(sum(CASE WHEN result='' THEN ? ELSE length(CAST(result AS BLOB)) END),0),count(*) FROM executions WHERE delivery IN ('pending','held')`, protocol.MaxResultBytes).Scan(&bytes, &count); e != nil {
		return nil, e
	}
	if bytes > PendingByteLimit-protocol.MaxResultBytes || count >= PendingLimit {
		return nil, ErrCapacity
	}
	b, e := json.Marshal(t)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO executions(id,task,status,dispatch_expires_at) VALUES(?,?,'ACCEPTED',?)", t.ID, string(b), t.DispatchExpiresAt); e != nil {
		return nil, e
	}
	return nil, tx.Commit()
}
func (s *State) markRunning(ctx context.Context, id string) error {
	res, e := s.db.ExecContext(ctx, "UPDATE executions SET status='RUNNING' WHERE id=? AND status='ACCEPTED' AND result='' AND delivery='pending'", id)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errors.New("execution cannot enter RUNNING")
	}
	return nil
}
func (s *State) finish(ctx context.Context, r protocol.Result) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(b) > protocol.MaxResultBytes {
		return errors.New("result exceeds reserved capacity")
	}
	res, e := s.db.ExecContext(ctx, "UPDATE executions SET status=?,result=? WHERE id=? AND result='' AND delivery='pending' AND status IN ('ACCEPTED','RUNNING')", r.Status, string(b), r.TaskID)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errors.New("terminal result is immutable")
	}
	return nil
}
func (s *State) Pending(ctx context.Context) ([]protocol.Result, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT result FROM executions WHERE delivery='pending' AND result<>'' ORDER BY id LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []protocol.Result{}
	for rows.Next() {
		var b string
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		r, e := protocol.DecodeResult([]byte(b))
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *State) Acknowledge(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, e := s.db.ExecContext(ctx, "UPDATE executions SET delivery='acknowledged',delivery_error='' WHERE id=? AND result<>'' AND delivery IN ('pending','acknowledged')", id)
	return changed(res, e)
}
