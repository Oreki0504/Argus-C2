package state

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

const MaxStoredTasks = 10000

func migrateTasks(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `ALTER TABLE nodes ADD COLUMN policy_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN task_state TEXT NOT NULL DEFAULT '';
CREATE TABLE dispatch_settings(id INTEGER PRIMARY KEY CHECK(id=1),key_digest TEXT NOT NULL);
INSERT INTO dispatch_settings VALUES(1,'');
CREATE TABLE tasks(
 sequence INTEGER PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,agent_id TEXT NOT NULL REFERENCES nodes(agent_id),
 epoch TEXT NOT NULL,payload BLOB NOT NULL,envelope BLOB,state TEXT NOT NULL,expires_at INTEGER NOT NULL,
 result BLOB,result_digest TEXT NOT NULL DEFAULT '',code TEXT NOT NULL DEFAULT ''
);
CREATE INDEX tasks_owner_pending ON tasks(agent_id,epoch,state,sequence);`)
	return err
}

func (s *Store) ConfigureSigner(ctx context.Context, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid task signing key")
	}
	digest := audit.Digest(key.Public().(ed25519.PublicKey))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	if err := tx.QueryRowContext(ctx, "SELECT key_digest FROM dispatch_settings WHERE id=1").Scan(&current); err != nil {
		return err
	}
	if current != "" && current != digest {
		return errors.New("task signing key changed; explicit recovery is required")
	}
	if current == "" {
		if _, err := tx.ExecContext(ctx, "UPDATE dispatch_settings SET key_digest=? WHERE id=1", digest); err != nil {
			return err
		}
		if err := audit.Append(ctx, tx, audit.Event{Kind: "signing_key_configured", ActorID: "local-operator", Source: "local", Status: "succeeded", PayloadDigest: digest}, 0); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Enqueue is local administration only. It commits exact payload bytes and the
// intent before the polling path is allowed to sign anything.
func (s *Store) Enqueue(ctx context.Context, id string, kind protocol.TaskType, actor string, ttl time.Duration, params ...json.RawMessage) (protocol.Task, error) {
	if len(params) > 1 {
		return protocol.Task{}, errors.New("expected one typed parameter object")
	}
	if !identity.Hex(id, 32) || ttl < time.Second || ttl > protocol.MaxLifetime*time.Second {
		return protocol.Task{}, errors.New("invalid task target or lifetime")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Task{}, err
	}
	defer tx.Rollback()
	var epoch, digest, keyDigest, worker string
	var received int64
	if err := tx.QueryRowContext(ctx, "SELECT enrollment_epoch,policy_digest,task_state,received_at FROM nodes WHERE agent_id=? AND enabled=1", id).Scan(&epoch, &digest, &worker, &received); err != nil {
		return protocol.Task{}, errors.New("node is not enabled")
	}
	if !identity.Hex(digest, 64) || worker != "ready" || received < time.Now().Add(-5*time.Minute).UnixNano() {
		return protocol.Task{}, errors.New("a recent ready task heartbeat is required")
	}
	if err := tx.QueryRowContext(ctx, "SELECT key_digest FROM dispatch_settings WHERE id=1").Scan(&keyDigest); err != nil || keyDigest == "" {
		return protocol.Task{}, errors.New("task signing is not configured")
	}
	if err := expireTasks(ctx, tx, id, time.Now().Unix()); err != nil {
		return protocol.Task{}, err
	}
	var total, pending int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks").Scan(&total); err != nil {
		return protocol.Task{}, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE agent_id=? AND state IN ('queued','dispatched')", id).Scan(&pending); err != nil {
		return protocol.Task{}, err
	}
	if total >= MaxStoredTasks || pending >= 10 {
		return protocol.Task{}, errors.New("task storage or node queue is full")
	}
	now := time.Now().Unix()
	t := protocol.Task{Version: 1, RequestID: identity.RandomID(), AgentID: id, EnrollmentEpoch: epoch, CreatedAt: now, ExpiresAt: now + int64(ttl/time.Second), Type: kind, TaskVersion: 1, Params: json.RawMessage(`{}`), ActorID: actor, PolicyDigest: digest}
	if len(params) == 1 {
		t.Params = append(json.RawMessage{}, params[0]...)
	}
	if err := t.Validate(); err != nil {
		return protocol.Task{}, err
	}
	data, err := json.Marshal(t)
	if err != nil {
		return protocol.Task{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(request_id,agent_id,epoch,payload,state,expires_at) VALUES(?,?,?,?,'queued',?)", t.RequestID, id, epoch, data, t.ExpiresAt); err != nil {
		return protocol.Task{}, err
	}
	if err := audit.Append(ctx, tx, audit.TaskEvent("task_queued", t, "local", "queued", "", audit.Digest(data)), 2); err != nil {
		return protocol.Task{}, err
	}
	return t, tx.Commit()
}

func authorizeTx(ctx context.Context, tx *sql.Tx, cert *x509.Certificate) (identity.Node, error) {
	n, err := identity.FromCertificate(cert)
	if err != nil {
		return n, err
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return n, errors.New("certificate is outside its validity window")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT 1 FROM nodes WHERE agent_id=? AND enrollment_epoch=? AND certificate_sha256=? AND enabled=1", n.AgentID, n.EnrollmentEpoch, identity.Fingerprint(cert)).Scan(&exists); err != nil {
		return n, errors.New("node is not authorized")
	}
	return n, nil
}

func (s *Store) Poll(ctx context.Context, cert *x509.Certificate, policyDigest string, key ed25519.PrivateKey, source string) ([]byte, error) {
	// A poll's policy digest is only an observation, never permission to change
	// an assignment. Deliver stale assignments unchanged for local rejection.
	if len(key) != ed25519.PrivateKeySize || !identity.Hex(policyDigest, 64) {
		return nil, errors.New("invalid dispatch configuration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	n, err := authorizeTx(ctx, tx, cert)
	if err != nil {
		return nil, err
	}
	var current string
	if err := tx.QueryRowContext(ctx, "SELECT key_digest FROM dispatch_settings WHERE id=1").Scan(&current); err != nil || current != audit.Digest(key.Public().(ed25519.PublicKey)) {
		return nil, errors.New("task signing configuration mismatch")
	}
	if err := expireTasks(ctx, tx, n.AgentID, time.Now().Unix()); err != nil {
		return nil, err
	}
	var payload, envelope []byte
	var status string
	err = tx.QueryRowContext(ctx, "SELECT payload,envelope,state FROM tasks WHERE agent_id=? AND epoch=? AND state IN ('queued','dispatched') AND expires_at>? ORDER BY sequence LIMIT 1", n.AgentID, n.EnrollmentEpoch, time.Now().Unix()).Scan(&payload, &envelope, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	t, err := protocol.DecodeTask(payload)
	if err != nil || t.AgentID != n.AgentID || t.EnrollmentEpoch != n.EnrollmentEpoch {
		return nil, errors.New("stored task is invalid")
	}
	if status == "queued" {
		envelope, err = signing.Sign(payload, key)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state='dispatched',envelope=? WHERE request_id=?", envelope, t.RequestID); err != nil {
			return nil, err
		}
		if err := audit.Append(ctx, tx, audit.TaskEvent("task_dispatched", t, source, "dispatched", "", audit.Digest(payload)), -1); err != nil {
			return nil, err
		}
	} else {
		_, signed, err := signing.VerifyPayload(envelope, key.Public().(ed25519.PublicKey))
		if err != nil || audit.Digest(signed) != audit.Digest(payload) {
			return nil, errors.New("stored task signature is invalid")
		}
	}
	return envelope, tx.Commit()
}

// Only undispatched tasks become terminal on expiration. Dispatched tasks stop
// being delivered but retain their reserved completion event for a late result.
func expireTasks(ctx context.Context, tx *sql.Tx, id string, now int64) error {
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM tasks WHERE agent_id=? AND state='queued' AND expires_at<=?", id, now)
	if err != nil {
		return err
	}
	var expired [][]byte
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, payload)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, payload := range expired {
		t, err := protocol.DecodeTask(payload)
		if err != nil {
			return err
		}
		status := "expired"
		code := "expired_before_dispatch"
		delta := -2
		if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,code=? WHERE request_id=?", status, code, t.RequestID); err != nil {
			return err
		}
		if err := audit.Append(ctx, tx, audit.TaskEvent("task_expired", t, "server", status, code, audit.Digest(payload)), delta); err != nil {
			return err
		}
	}
	return nil
}

func cancelNodeTasks(ctx context.Context, tx *sql.Tx, id string) error {
	rows, err := tx.QueryContext(ctx, "SELECT payload,state FROM tasks WHERE agent_id=? AND state IN ('queued','dispatched')", id)
	if err != nil {
		return err
	}
	type item struct {
		payload []byte
		state   string
	}
	var items []item
	for rows.Next() {
		var i item
		if err := rows.Scan(&i.payload, &i.state); err != nil {
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
	for _, i := range items {
		t, err := protocol.DecodeTask(i.payload)
		if err != nil {
			return err
		}
		delta := -1
		status := "indeterminate"
		if i.state == "queued" {
			delta = -2
			status = "rejected"
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,code='node_disabled' WHERE request_id=?", status, t.RequestID); err != nil {
			return err
		}
		if err := audit.Append(ctx, tx, audit.TaskEvent("task_cancelled", t, "local", status, "node_disabled", audit.Digest(i.payload)), delta); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SubmitResult(ctx context.Context, cert *x509.Certificate, data []byte, source string) (protocol.ResultAck, error) {
	if len(data) > protocol.MaxDispatchResultBytes {
		return protocol.ResultAck{}, errors.New("result too large")
	}
	r, err := protocol.DecodeResult(data)
	if err != nil {
		return protocol.ResultAck{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.ResultAck{}, err
	}
	defer tx.Rollback()
	n, err := authorizeTx(ctx, tx, cert)
	if err != nil {
		return protocol.ResultAck{}, err
	}
	if r.AgentID != n.AgentID || r.Epoch != n.EnrollmentEpoch {
		return protocol.ResultAck{}, errors.New("result identity mismatch")
	}
	var payload []byte
	var status, digest string
	if err := tx.QueryRowContext(ctx, "SELECT payload,state,result_digest FROM tasks WHERE request_id=? AND agent_id=? AND epoch=?", r.RequestID, n.AgentID, n.EnrollmentEpoch).Scan(&payload, &status, &digest); err != nil {
		return protocol.ResultAck{}, errors.New("result has no matching assignment")
	}
	t, err := protocol.DecodeTask(payload)
	if err != nil || r.CheckAssignment(t) != nil {
		return protocol.ResultAck{}, errors.New("result type mismatch")
	}
	if r.Status != protocol.Rejected && r.Status != protocol.Expired && r.PolicyDigest != t.PolicyDigest {
		return protocol.ResultAck{}, errors.New("result policy mismatch")
	}
	want := audit.Digest(data)
	if digest != "" {
		if digest != want {
			return protocol.ResultAck{}, errors.New("terminal result cannot be overwritten")
		}
	} else {
		if status != "dispatched" {
			return protocol.ResultAck{}, errors.New("task was not dispatched")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state=?,result=?,result_digest=?,code=? WHERE request_id=?", r.Status, data, want, r.ErrorCode, r.RequestID); err != nil {
			return protocol.ResultAck{}, err
		}
		event := audit.TaskEvent("result_received", t, source, string(r.Status), string(r.ErrorCode), audit.Digest(payload))
		event.PolicyDigest = r.PolicyDigest
		event.ResultDigest = want
		if err := audit.Append(ctx, tx, event, -1); err != nil {
			return protocol.ResultAck{}, err
		}
	}
	ack := protocol.ResultAck{Version: 1, AgentID: n.AgentID, Epoch: n.EnrollmentEpoch, RequestID: r.RequestID, ResultDigest: want}
	return ack, tx.Commit()
}

type TaskRecord struct {
	Sequence int64           `json:"sequence"`
	Task     protocol.Task   `json:"task"`
	State    string          `json:"state"`
	Code     string          `json:"code"`
	Result   json.RawMessage `json:"result"`
}

func (s *Store) Tasks(ctx context.Context, after int64, limit int) ([]TaskRecord, error) {
	if after < 0 || limit < 1 || limit > 200 {
		return nil, errors.New("invalid task page")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT sequence,payload,state,code,result,result_digest FROM tasks WHERE sequence>? ORDER BY sequence LIMIT ?", after, limit)
	if err != nil {
		return nil, err
	}
	result := []TaskRecord{}
	for rows.Next() {
		var r TaskRecord
		var payload, data []byte
		var resultDigest string
		if err := rows.Scan(&r.Sequence, &payload, &r.State, &r.Code, &data, &resultDigest); err != nil {
			rows.Close()
			return nil, err
		}
		r.Task, err = protocol.DecodeTask(payload)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if len(data) > 0 {
			decoded, err := protocol.DecodeResult(data)
			if err != nil || audit.Digest(data) != resultDigest || decoded.CheckAssignment(r.Task) != nil {
				rows.Close()
				return nil, errors.New("stored task result is corrupt")
			}
		}
		r.Result = json.RawMessage(data)
		result = append(result, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "tasks_read", ActorID: "local-operator", Source: "local", Status: "succeeded"}, 0); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}
func (s *Store) Audit(ctx context.Context, after int64, limit int) (audit.Page, error) {
	return audit.Read(ctx, s.db, after, limit)
}
