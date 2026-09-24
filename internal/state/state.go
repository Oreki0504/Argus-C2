// Package state stores enrollment and the latest node telemetry in SQLite.
package state

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

var ErrUnauthorized = errors.New("invalid, expired, or consumed enrollment token")
var ErrRateLimited = errors.New("heartbeat received too soon")

const MaxNodes = 1000

type Store struct{ db *sql.DB }

// Open requires an operator-controlled parent and a private state directory.
// The application never accepts a database path from the network.
func Open(dir string) (*Store, error) {
	db, err := localdb.Open(dir, "argus.db", true)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version < 0 || version > 2 {
		return errors.New("unsupported database schema version")
	}
	if version == 0 {
		_, err = tx.ExecContext(ctx, `
CREATE TABLE enrollment_tokens (
 token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
);
CREATE TABLE nodes (
 agent_id TEXT PRIMARY KEY, enrollment_epoch TEXT NOT NULL, certificate_sha256 TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), enrolled_at INTEGER NOT NULL,
 received_at INTEGER NOT NULL DEFAULT 0, heartbeat BLOB
);
PRAGMA user_version=1;`)
		if err != nil {
			return err
		}
	}
	if version < 2 {
		if err := migrateTasks(ctx, tx); err != nil {
			return err
		}
		if err := audit.Initialize(ctx, tx); err != nil {
			return err
		}
		var enabled int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE enabled=1").Scan(&enabled); err != nil {
			return err
		}
		if err := audit.Append(ctx, tx, audit.Event{Kind: "state_initialized", ActorID: "local-operator", Source: "local", Status: "succeeded", Code: "server_schema_2"}, enabled); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
			return err
		}
	}
	if err := audit.Verify(ctx, tx); err != nil {
		return err
	}
	var reserved, expected int
	if err := tx.QueryRowContext(ctx, "SELECT reserved FROM audit_head WHERE id=1").Scan(&reserved); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM nodes WHERE enabled=1)+COALESCE(SUM(CASE state WHEN 'queued' THEN 2 WHEN 'dispatched' THEN 1 ELSE 0 END),0) FROM tasks").Scan(&expected); err != nil {
		return err
	}
	if reserved != expected {
		return errors.New("inconsistent server audit reservations")
	}
	return tx.Commit()
}

func tokenHash(token string) (string, error) {
	if !identity.Hex(token, 64) {
		return "", ErrUnauthorized
	}
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:]), nil
}

// IssueToken returns the secret once. Only its SHA-256 digest is persisted.
func (s *Store) IssueToken(ctx context.Context, ttl time.Duration) (string, error) {
	if ttl < time.Second || ttl > 15*time.Minute {
		return "", errors.New("token lifetime must be between 1 second and 15 minutes")
	}
	token := identity.RandomID() + identity.RandomID()
	hash, _ := tokenHash(token)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	now := time.Now()
	if _, err := tx.ExecContext(ctx, "DELETE FROM enrollment_tokens WHERE expires_at <= ? OR consumed=1", now.Unix()); err != nil {
		return "", err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM enrollment_tokens").Scan(&count); err != nil {
		return "", err
	}
	if count >= MaxNodes {
		return "", errors.New("pending token limit reached")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO enrollment_tokens(token_hash,expires_at) VALUES(?,?)", hash, now.Add(ttl).Unix()); err != nil {
		return "", err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "token_issued", ActorID: "local-operator", Source: "local", Status: "succeeded"}, 0); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// Register atomically consumes a token and inserts exactly one identity.
// A failed commit or registration leaves the token available for a valid retry.
func (s *Store) Register(ctx context.Context, token string, r identity.Registration) error {
	return s.RegisterFrom(ctx, token, r, "local")
}
func (s *Store) RegisterFrom(ctx context.Context, token string, r identity.Registration, source string) error {
	hash, err := tokenHash(token)
	if err != nil {
		return err
	}
	if (identity.Node{AgentID: r.AgentID, EnrollmentEpoch: r.EnrollmentEpoch}).Validate() != nil || !identity.Hex(r.CertificateSHA256, 64) || !r.Enabled {
		return errors.New("invalid registration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE enrollment_tokens SET consumed=1 WHERE token_hash=? AND consumed=0 AND expires_at>?", hash, time.Now().Unix())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrUnauthorized
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes").Scan(&count); err != nil {
		return err
	}
	if count >= MaxNodes {
		return errors.New("node limit reached")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO nodes(agent_id,enrollment_epoch,certificate_sha256,enabled,enrolled_at) VALUES(?,?,?,1,?)", r.AgentID, r.EnrollmentEpoch, r.CertificateSHA256, time.Now().Unix())
	if err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "node_enrolled", AgentID: r.AgentID, Epoch: r.EnrollmentEpoch, Source: source, Status: "succeeded"}, 1); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Authorize(cert *x509.Certificate) (identity.Node, error) {
	n, err := identity.FromCertificate(cert)
	if err != nil {
		return identity.Node{}, err
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return identity.Node{}, errors.New("expired or future certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var found int
	err = s.db.QueryRowContext(ctx, "SELECT 1 FROM nodes WHERE agent_id=? AND enrollment_epoch=? AND certificate_sha256=? AND enabled=1", n.AgentID, n.EnrollmentEpoch, identity.Fingerprint(cert)).Scan(&found)
	if err != nil {
		return identity.Node{}, errors.New("node identity is not authorized")
	}
	return n, nil
}

func (s *Store) Disable(ctx context.Context, id string) error {
	if !identity.Hex(id, 32) {
		return errors.New("invalid node ID")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT enabled FROM nodes WHERE agent_id=?", id).Scan(&enabled); err != nil {
		return errors.New("node not found")
	}
	if !enabled {
		return tx.Commit()
	}
	res, err := tx.ExecContext(ctx, "UPDATE nodes SET enabled=0 WHERE agent_id=?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("node not found")
	}
	if err := cancelNodeTasks(ctx, tx, id); err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "node_disabled", AgentID: id, ActorID: "local-operator", Source: "local", Status: "succeeded"}, -1); err != nil {
		return err
	}
	return tx.Commit()
}

// SaveHeartbeat derives identity from the verified certificate, then checks the
// registration again in the write transaction. Only the latest report is kept.
func (s *Store) SaveHeartbeat(ctx context.Context, cert *x509.Certificate, h protocol.Heartbeat) error {
	n, err := s.Authorize(cert)
	if err != nil {
		return err
	}
	if err := h.Validate(); err != nil {
		return err
	}
	if h.AgentID != n.AgentID || h.EnrollmentEpoch != n.EnrollmentEpoch {
		return errors.New("heartbeat identity mismatch")
	}
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last int64
	err = tx.QueryRowContext(ctx, "SELECT received_at FROM nodes WHERE agent_id=? AND enrollment_epoch=? AND certificate_sha256=? AND enabled=1", n.AgentID, n.EnrollmentEpoch, identity.Fingerprint(cert)).Scan(&last)
	if err != nil {
		return errors.New("node identity is not authorized")
	}
	now := time.Now().UnixNano()
	if now-last < int64(5*time.Second) {
		return ErrRateLimited
	}
	if _, err := tx.ExecContext(ctx, "UPDATE nodes SET heartbeat=?,received_at=?,policy_digest=?,task_state=? WHERE agent_id=?", data, now, h.PolicyDigest, h.TaskState, n.AgentID); err != nil {
		return err
	}
	return tx.Commit()
}

type Snapshot struct {
	AgentID         string          `json:"agent_id"`
	EnrollmentEpoch string          `json:"enrollment_epoch"`
	Enabled         bool            `json:"enabled"`
	EnrolledAt      int64           `json:"enrolled_at"`
	ReceivedAt      int64           `json:"received_at_unix_nano"`
	Heartbeat       json.RawMessage `json:"heartbeat"`
	PolicyDigest    string          `json:"policy_digest"`
	TaskState       string          `json:"task_state"`
}

// Snapshots is a local operator API, never an unauthenticated HTTP route.
func (s *Store) Snapshots(ctx context.Context) ([]Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT agent_id,enrollment_epoch,enabled,enrolled_at,received_at,heartbeat,policy_digest,task_state FROM nodes ORDER BY agent_id LIMIT ?", MaxNodes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Snapshot{}
	for rows.Next() {
		var v Snapshot
		var heartbeat []byte
		if err := rows.Scan(&v.AgentID, &v.EnrollmentEpoch, &v.Enabled, &v.EnrolledAt, &v.ReceivedAt, &heartbeat, &v.PolicyDigest, &v.TaskState); err != nil {
			return nil, err
		}
		v.Heartbeat = json.RawMessage(heartbeat)
		result = append(result, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "nodes_read", ActorID: "local-operator", Source: "local", Status: "succeeded"}, 0); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}
