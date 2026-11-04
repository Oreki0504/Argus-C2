package agent

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"path/filepath"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type DeliveryRecord struct {
	TaskID   string              `json:"task_id"`
	Status   protocol.TaskStatus `json:"status"`
	Delivery string              `json:"delivery"`
	Reason   string              `json:"reason"`
	Bytes    int64               `json:"bytes"`
}

// OpenLocal permits offline maintenance even when the certificate has expired.
// It still checks the local key pair and persisted identity and takes the lock.
func OpenLocal(dir string) (*State, error) {
	pair, e := transport.Pair(filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	id, e := identity.FromCertificate(cert)
	if e != nil {
		return nil, e
	}
	return OpenState(dir, id, false)
}

func (s *State) Deliveries(ctx context.Context, after string) ([]DeliveryRecord, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT id,status,delivery,delivery_error,length(CAST(result AS BLOB)) FROM executions WHERE id>? ORDER BY id LIMIT 200", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []DeliveryRecord{}
	for rows.Next() {
		var r DeliveryRecord
		if e = rows.Scan(&r.TaskID, &r.Status, &r.Delivery, &r.Reason, &r.Bytes); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *State) Delivery(ctx context.Context, id string) (DeliveryRecord, error) {
	var r DeliveryRecord
	e := s.db.QueryRowContext(ctx, "SELECT id,status,delivery,delivery_error,length(CAST(result AS BLOB)) FROM executions WHERE id=?", id).Scan(&r.TaskID, &r.Status, &r.Delivery, &r.Reason, &r.Bytes)
	return r, e
}
func (s *State) ResultBytes(ctx context.Context, id string) ([]byte, error) {
	var b, delivery string
	if e := s.db.QueryRowContext(ctx, "SELECT result,delivery FROM executions WHERE id=?", id).Scan(&b, &delivery); e != nil {
		return nil, e
	}
	if delivery == "discarded" {
		return nil, ErrResultDiscarded
	}
	if b == "" {
		return nil, errors.New("no persisted result")
	}
	if _, e := protocol.DecodeResult([]byte(b)); e != nil {
		return nil, e
	}
	return []byte(b), nil
}
func (s *State) Hold(ctx context.Context, id, code string) error {
	switch code {
	case "result_conflict", "task_rejected", "task_not_found", "result_invalid":
	default:
		return errors.New("not a permanent result rejection")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, e := s.db.ExecContext(ctx, "UPDATE executions SET delivery='held',delivery_error=? WHERE id=? AND delivery='pending' AND result<>''", code, id)
	return changed(res, e)
}
func (s *State) Retry(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, e := s.db.ExecContext(ctx, "UPDATE executions SET delivery='pending',delivery_error='' WHERE id=? AND delivery='held' AND result<>''", id)
	return changed(res, e)
}
func (s *State) Discard(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// One atomic statement preserves the assignment and terminal execution state.
	// discarded is deliberately distinct from a server acknowledgment.
	res, e := s.db.ExecContext(ctx, "UPDATE executions SET result='',delivery='discarded',delivery_error='operator_discarded' WHERE id=? AND result<>'' AND status IN ('SUCCEEDED','FAILED','UNKNOWN') AND delivery<>'discarded'", id)
	return changed(res, e)
}
func changed(res sql.Result, e error) error {
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errors.New("no eligible local result; inspect its delivery state")
	}
	return nil
}

type ResultCapacity struct {
	Count     int64 `json:"pending_and_held_count"`
	Bytes     int64 `json:"reserved_and_result_bytes"`
	Held      int64 `json:"held_count"`
	Discarded int64 `json:"discarded_count"`
}

func (s *State) Capacity(ctx context.Context) (ResultCapacity, error) {
	var c ResultCapacity
	e := s.db.QueryRowContext(ctx, `SELECT
 coalesce(sum(CASE WHEN delivery IN ('pending','held') THEN 1 ELSE 0 END),0),
 coalesce(sum(CASE WHEN delivery IN ('pending','held') THEN CASE WHEN result='' THEN ? ELSE length(CAST(result AS BLOB)) END ELSE 0 END),0),
 coalesce(sum(CASE WHEN delivery='held' THEN 1 ELSE 0 END),0),
 coalesce(sum(CASE WHEN delivery='discarded' THEN 1 ELSE 0 END),0) FROM executions`, protocol.MaxResultBytes).Scan(&c.Count, &c.Bytes, &c.Held, &c.Discarded)
	return c, e
}
