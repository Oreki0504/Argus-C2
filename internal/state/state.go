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
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	_ "modernc.org/sqlite"
)

var ErrUnauthorized = errors.New("invalid, expired, or consumed enrollment token")
var ErrRateLimited = errors.New("heartbeat received too soon")

const MaxNodes = 1000

type Store struct{ db *sql.DB }

// Open requires an operator-controlled parent and a private state directory.
// The application never accepts a database path from the network.
func Open(dir string) (*Store, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("state directory must be private, real, and operator-controlled")
	}
	path := filepath.Join(dir, "argus.db")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		err = f.Close()
	}
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	for _, name := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		st, err := os.Lstat(name)
		if os.IsNotExist(err) && name != path {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
			return nil, errors.New("database and sidecars must be private regular files")
		}
	}
	p := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{"_pragma": {"busy_timeout(2000)", "foreign_keys(1)", "journal_mode(WAL)", "synchronous(FULL)"}, "_txlock": {"immediate"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	if version != 0 && version != 1 {
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
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// Register atomically consumes a token and inserts exactly one identity.
// A failed commit or registration leaves the token available for a valid retry.
func (s *Store) Register(ctx context.Context, token string, r identity.Registration) error {
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
	res, err := s.db.ExecContext(ctx, "UPDATE nodes SET enabled=0 WHERE agent_id=?", id)
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
	return nil
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
	if _, err := tx.ExecContext(ctx, "UPDATE nodes SET heartbeat=?,received_at=? WHERE agent_id=?", data, now, n.AgentID); err != nil {
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
}

// Snapshots is a local operator API, never an unauthenticated HTTP route.
func (s *Store) Snapshots(ctx context.Context) ([]Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT agent_id,enrollment_epoch,enabled,enrolled_at,received_at,heartbeat FROM nodes ORDER BY agent_id LIMIT ?", MaxNodes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Snapshot{}
	for rows.Next() {
		var v Snapshot
		var heartbeat []byte
		if err := rows.Scan(&v.AgentID, &v.EnrollmentEpoch, &v.Enabled, &v.EnrolledAt, &v.ReceivedAt, &heartbeat); err != nil {
			return nil, err
		}
		v.Heartbeat = json.RawMessage(heartbeat)
		result = append(result, v)
	}
	return result, rows.Err()
}
