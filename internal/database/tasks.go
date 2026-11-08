package database

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const taskColumns = "id,node_id,task_type,parameters,status,created_at,dispatch_expires_at,execution_timeout_ms,result_due_at"

type scanner interface{ Scan(...any) error }

func scanTask(row scanner) (protocol.Task, error) {
	var t protocol.Task
	var params string
	e := row.Scan(&t.ID, &t.NodeID, &t.Type, &params, &t.Status, &t.CreatedAt, &t.DispatchExpiresAt, &t.ExecutionTimeoutMS, &t.ResultDueAt)
	t.Params = json.RawMessage(params)
	return t, e
}
func (s *Store) CreateTask(ctx context.Context, actor string, r protocol.TaskRequest) (protocol.Task, error) {
	b, e := json.Marshal(r)
	if e != nil {
		return protocol.Task{}, e
	}
	if _, e = protocol.DecodeTaskRequest(b); e != nil {
		return protocol.Task{}, e
	}
	now := s.now().Unix()
	t := protocol.Task{ID: identity.RandomID(), NodeID: r.NodeID, Type: r.Type, Params: r.Params, Status: protocol.Pending, CreatedAt: now, DispatchExpiresAt: now + int64(r.TTLSeconds), ExecutionTimeoutMS: r.ExecutionTimeoutMS, ResultDueAt: now + int64(r.TTLSeconds) + protocol.ResultGraceSeconds}
	e = s.Write(ctx, func(tx *sql.Tx) error {
		var status string
		if e := tx.QueryRowContext(ctx, "SELECT status FROM nodes WHERE id=?", t.NodeID).Scan(&status); e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				return ErrNotFound
			}
			return e
		}
		if status != "active" {
			return ErrNodeDisabled
		}
		if e := expire(ctx, tx, s.now().Unix()); e != nil {
			return e
		}
		var count int
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM tasks WHERE node_id=? AND status IN ('PENDING','ACCEPTED','RUNNING')", t.NodeID).Scan(&count); e != nil {
			return e
		}
		if count >= 100 {
			return ErrConflict
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO tasks("+taskColumns+") VALUES(?,?,?,?,?,?,?,?,?)", t.ID, t.NodeID, t.Type, string(t.Params), t.Status, t.CreatedAt, t.DispatchExpiresAt, t.ExecutionTimeoutMS, t.ResultDueAt); e != nil {
			return e
		}
		return Audit(ctx, tx, actor, "task.create", t.NodeID, t.ID, "accepted")
	})
	return t, e
}
func (s *Store) Poll(ctx context.Context, c *x509.Certificate) (*protocol.Task, error) {
	return s.PollWithMonitoring(ctx, c, false)
}

// PollWithMonitoring only creates bounded, fixed read-only monitoring work
// when the operator's queue is empty. Agent local policy remains authoritative.
func (s *Store) PollWithMonitoring(ctx context.Context, c *x509.Certificate, monitoring bool) (*protocol.Task, error) {
	var task *protocol.Task
	e := s.Write(ctx, func(tx *sql.Tx) error {
		id, e := Authorize(ctx, tx, c)
		if e != nil {
			return e
		}
		if e = expire(ctx, tx, s.now().Unix()); e != nil {
			return e
		}
		// One task in flight per node. Repeated delivery is intentionally idempotent.
		t, e := scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE node_id=? AND status IN ('PENDING','ACCEPTED','RUNNING') ORDER BY CASE WHEN status='PENDING' THEN 1 ELSE 0 END,created_at,id LIMIT 1", id))
		if errors.Is(e, sql.ErrNoRows) && monitoring {
			t, e = monitoringTask(ctx, tx, id, s.now().Unix())
		}
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if t.Status == protocol.Pending {
			t.Status = protocol.Accepted
			if e = updateOne(ctx, tx, "UPDATE tasks SET status='ACCEPTED' WHERE id=? AND status='PENDING'", t.ID); e != nil {
				return e
			}
			if e = Audit(ctx, tx, id, "task.accept", id, t.ID, "accepted"); e != nil {
				return e
			}
		}
		task = &t
		return nil
	})
	return task, e
}

func monitoringTask(ctx context.Context, tx *sql.Tx, node string, now int64) (protocol.Task, error) {
	for _, item := range []struct {
		kind     protocol.TaskType
		interval int64
	}{
		{protocol.SystemInfo, 3600}, {protocol.SystemMetrics, 60},
	} {
		var last sql.NullInt64
		if err := tx.QueryRowContext(ctx, "SELECT max(created_at) FROM tasks WHERE node_id=? AND task_type=?", node, item.kind).Scan(&last); err != nil {
			return protocol.Task{}, err
		}
		if last.Valid && now-last.Int64 < item.interval {
			continue
		}
		t := protocol.Task{ID: identity.RandomID(), NodeID: node, Type: item.kind, Params: json.RawMessage(`{}`),
			Status: protocol.Pending, CreatedAt: now, DispatchExpiresAt: now + 60, ExecutionTimeoutMS: 10000, ResultDueAt: now + 60 + protocol.ResultGraceSeconds}
		if _, err := tx.ExecContext(ctx, "INSERT INTO tasks("+taskColumns+") VALUES(?,?,?,?,?,?,?,?,?)", t.ID, t.NodeID, t.Type, string(t.Params), t.Status, t.CreatedAt, t.DispatchExpiresAt, t.ExecutionTimeoutMS, t.ResultDueAt); err != nil {
			return protocol.Task{}, err
		}
		return t, Audit(ctx, tx, "console-monitor", "task.create", node, t.ID, "accepted")
	}
	return protocol.Task{}, sql.ErrNoRows
}
func (s *Store) Running(ctx context.Context, c *x509.Certificate, id string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		node, e := Authorize(ctx, tx, c)
		if e != nil {
			return e
		}
		t, e := scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE id=? AND node_id=?", id, node))
		if errors.Is(e, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		if e != nil {
			return e
		}
		now := s.now().Unix()
		if t.Status == protocol.Running {
			if now >= t.ResultDueAt {
				return ErrConflict
			}
			return nil // Retry never extends the original result deadline.
		}
		if t.Status != protocol.Accepted || t.DispatchExpiresAt <= now {
			return ErrConflict
		}
		if e = updateOne(ctx, tx, "UPDATE tasks SET status='RUNNING',result_due_at=?,execution_authorized_at=? WHERE id=? AND status='ACCEPTED'", now+int64((t.ExecutionTimeoutMS+999)/1000)+protocol.ResultGraceSeconds, now, id); e != nil {
			return e
		}
		return Audit(ctx, tx, node, "task.run", node, id, "running")
	})
}
func (s *Store) SubmitResult(ctx context.Context, c *x509.Certificate, r protocol.Result) error {
	if e := r.Validate(); e != nil {
		return ErrInvalidResult
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		node, e := Authorize(ctx, tx, c)
		if e != nil {
			return e
		}
		if r.NodeID != node {
			return ErrUnauthorized
		}
		t, e := scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE id=? AND node_id=?", r.TaskID, node))
		if errors.Is(e, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		if e != nil {
			return e
		}
		if e = r.CheckAssignment(t); e != nil {
			return ErrInvalidResult
		}
		old, e := resultTx(ctx, tx, t.ID)
		if e == nil {
			equal, compareErr := protocol.EquivalentResults(t, old, r)
			if compareErr != nil {
				return compareErr
			}
			if !equal {
				return ErrResultConflict
			}
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if t.Status != protocol.Accepted && t.Status != protocol.Running && t.Status != protocol.Unknown {
			return ErrTaskRejected
		}
		if r.Status == protocol.Succeeded {
			var authorizedAt int64
			if e = tx.QueryRowContext(ctx, "SELECT execution_authorized_at FROM tasks WHERE id=?", t.ID).Scan(&authorizedAt); e != nil {
				return e
			}
			if authorizedAt == 0 || t.Status == protocol.Accepted {
				return ErrTaskRejected
			}
		}
		if e = insertResult(ctx, tx, r, s.now().Unix()); e != nil {
			return e
		}
		if e = updateOne(ctx, tx, "UPDATE tasks SET status=? WHERE id=? AND status IN ('ACCEPTED','RUNNING','UNKNOWN')", r.Status, t.ID); e != nil {
			return e
		}
		return Audit(ctx, tx, node, "task.complete", node, t.ID, string(r.Status))
	})
}
func insertResult(ctx context.Context, tx *sql.Tx, r protocol.Result, receivedAt int64) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO results(task_id,node_id,status,payload,error,completed_at,received_at) VALUES(?,?,?,?,?,?,?)", r.TaskID, r.NodeID, r.Status, string(r.Payload), r.Error, r.CompletedAt, receivedAt)
	return e
}

// A successful statement must actually perform its guarded transition. Otherwise
// the enclosing transaction must not commit a result or an audit event for it.
func updateOne(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}
func resultTx(ctx context.Context, tx *sql.Tx, id string) (protocol.Result, error) {
	var r protocol.Result
	var p string
	e := tx.QueryRowContext(ctx, "SELECT task_id,node_id,status,payload,error,completed_at FROM results WHERE task_id=?", id).Scan(&r.TaskID, &r.NodeID, &r.Status, &p, &r.Error, &r.CompletedAt)
	r.Payload = json.RawMessage(p)
	return r, e
}

type TaskView struct {
	Task                  protocol.Task    `json:"task"`
	Result                *protocol.Result `json:"result,omitempty"`
	ExecutionAuthorizedAt int64            `json:"execution_authorized_at,omitempty"`
	ResultReceivedAt      int64            `json:"result_received_at,omitempty"`
}

func (s *Store) Task(ctx context.Context, id string) (TaskView, error) {
	var v TaskView
	e := s.Write(ctx, func(tx *sql.Tx) error {
		if e := expire(ctx, tx, s.now().Unix()); e != nil {
			return e
		}
		var e error
		v.Task, e = scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE id=?", id))
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if e = tx.QueryRowContext(ctx, "SELECT execution_authorized_at FROM tasks WHERE id=?", id).Scan(&v.ExecutionAuthorizedAt); e != nil {
			return e
		}
		r, e := resultTx(ctx, tx, id)
		if e == nil {
			v.Result = &r
			if e = tx.QueryRowContext(ctx, "SELECT received_at FROM results WHERE task_id=?", id).Scan(&v.ResultReceivedAt); e != nil {
				return e
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		return nil
	})
	return v, e
}
func (s *Store) Tasks(ctx context.Context, after string) ([]protocol.Task, error) {
	out := []protocol.Task{}
	e := s.Write(ctx, func(tx *sql.Tx) error {
		if e := expire(ctx, tx, s.now().Unix()); e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE id>? ORDER BY id LIMIT 200", after)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			t, e := scanTask(rows)
			if e != nil {
				return e
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, e
}
func expire(ctx context.Context, tx *sql.Tx, now int64) error {
	rows, e := tx.QueryContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE (status='PENDING' AND dispatch_expires_at<=?) OR (status IN ('ACCEPTED','RUNNING') AND result_due_at<=?)", now, now)
	if e != nil {
		return e
	}
	var items []protocol.Task
	for rows.Next() {
		t, e := scanTask(rows)
		if e != nil {
			rows.Close()
			return e
		}
		items = append(items, t)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, t := range items {
		status := protocol.Unknown
		if t.Status == protocol.Pending {
			status = protocol.Failed
			if e = insertResult(ctx, tx, protocol.NewResult(t, status, "expired_before_dispatch"), now); e != nil {
				return e
			}
		}
		if e = updateOne(ctx, tx, "UPDATE tasks SET status=? WHERE id=? AND status=?", status, t.ID, t.Status); e != nil {
			return e
		}
		if e = Audit(ctx, tx, "server", "task.expire", t.NodeID, t.ID, string(status)); e != nil {
			return e
		}
	}
	return nil
}

// ExpireTasks applies the existing request-driven expiry rules for Console lists.
func (s *Store) ExpireTasks(ctx context.Context) error {
	return s.Write(ctx, func(tx *sql.Tx) error { return expire(ctx, tx, s.now().Unix()) })
}
func finishOutstanding(ctx context.Context, tx *sql.Tx, id, code string, now int64) error {
	rows, e := tx.QueryContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE node_id=? AND status IN ('PENDING','ACCEPTED','RUNNING')", id)
	if e != nil {
		return e
	}
	var items []protocol.Task
	for rows.Next() {
		t, e := scanTask(rows)
		if e != nil {
			rows.Close()
			return e
		}
		items = append(items, t)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, t := range items {
		status := protocol.Unknown
		if t.Status == protocol.Pending {
			status = protocol.Failed
		}
		if e = insertResult(ctx, tx, protocol.NewResult(t, status, code), now); e != nil {
			return e
		}
		if e = updateOne(ctx, tx, "UPDATE tasks SET status=? WHERE id=? AND status=?", status, t.ID, t.Status); e != nil {
			return e
		}
	}
	return nil
}
