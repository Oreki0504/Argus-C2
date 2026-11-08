// Package database uses ordinary SQLite transactions for fleet state and audit.
package database

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

var ErrUnauthorized = errors.New("unauthorized")
var ErrConflict = errors.New("state conflict")
var ErrNodeDisabled = fmt.Errorf("%w: node disabled", ErrConflict)
var ErrNotFound = errors.New("not found")
var ErrTaskNotFound = fmt.Errorf("%w: assigned task", ErrNotFound)
var ErrResultConflict = fmt.Errorf("%w: result differs", ErrConflict)
var ErrTaskRejected = fmt.Errorf("%w: task cannot accept result", ErrConflict)
var ErrInvalidResult = errors.New("invalid result for assigned task")
var ErrInvalidRenewal = errors.New("renewal public key differs")

type Store struct {
	DB    *sql.DB
	clock func() time.Time
}

func (s *Store) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

const SchemaVersion = 104
const applicationID = 0x41524753 // ARGS

const schema = `
CREATE TABLE nodes(id TEXT PRIMARY KEY,hostname TEXT NOT NULL,certificate_fingerprint TEXT NOT NULL UNIQUE,status TEXT NOT NULL CHECK(status IN ('active','disabled')),last_seen_at INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,certificate_expires_at INTEGER NOT NULL,certificate TEXT NOT NULL,previous_fingerprint TEXT NOT NULL DEFAULT '',previous_until INTEGER NOT NULL DEFAULT 0,protocol_version INTEGER NOT NULL DEFAULT 1,agent_version TEXT NOT NULL DEFAULT 'unknown');
CREATE TABLE enrollment_tokens(digest TEXT PRIMARY KEY,expires_at INTEGER NOT NULL,node_id TEXT REFERENCES nodes(id),csr_fingerprint TEXT NOT NULL DEFAULT '');
CREATE TABLE tasks(id TEXT PRIMARY KEY,node_id TEXT NOT NULL REFERENCES nodes(id),task_type TEXT NOT NULL,parameters TEXT NOT NULL CHECK(json_valid(parameters)),status TEXT NOT NULL CHECK(status IN ('PENDING','ACCEPTED','RUNNING','SUCCEEDED','FAILED','UNKNOWN')),created_at INTEGER NOT NULL,dispatch_expires_at INTEGER NOT NULL,execution_timeout_ms INTEGER NOT NULL,result_due_at INTEGER NOT NULL,execution_authorized_at INTEGER NOT NULL DEFAULT 0);
CREATE INDEX tasks_node_status ON tasks(node_id,status,created_at DESC,id DESC);
CREATE INDEX tasks_created ON tasks(created_at DESC,id DESC);
CREATE INDEX tasks_node_created ON tasks(node_id,created_at DESC,id DESC);
CREATE INDEX tasks_status_created ON tasks(status,created_at DESC,id DESC);
CREATE TABLE results(task_id TEXT PRIMARY KEY REFERENCES tasks(id),node_id TEXT NOT NULL REFERENCES nodes(id),status TEXT NOT NULL,payload TEXT NOT NULL CHECK(json_valid(payload)),error TEXT NOT NULL,completed_at INTEGER NOT NULL,received_at INTEGER NOT NULL CHECK(received_at>0));
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,node_id TEXT NOT NULL,task_id TEXT NOT NULL,status TEXT NOT NULL);
PRAGMA user_version=102;PRAGMA application_id=1095911251;`

func Open(dir string, create bool) (*Store, error) {
	db, e := localdb.Open(dir, "argus.db", create)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
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
		if _, e = tx.Exec(schema + consoleSchema + consoleAccountSchema); e != nil {
			tx.Rollback()
			return fail(e)
		}
		if e = tx.Commit(); e != nil {
			return fail(e)
		}
	} else if version != SchemaVersion {
		return fail(errors.New("incompatible server database schema; preserve existing state and use a supported database"))
	}
	if e = db.QueryRow("PRAGMA application_id").Scan(&component); e != nil {
		return fail(e)
	}
	if component != applicationID {
		return fail(errors.New("database belongs to another component"))
	}
	return &Store{DB: db}, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) Write(ctx context.Context, f func(*sql.Tx) error) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = authorizeConsoleContext(ctx, tx); e != nil {
		return e
	}
	if e = f(tx); e != nil {
		return e
	}
	return tx.Commit()
}

// Hashes here protect high-entropy bearer tokens at rest; they are not transport checks.
func TokenDigest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

const AuditCapacity = 100000

func Audit(ctx context.Context, tx *sql.Tx, actor, action, node, task, status string) error {
	return auditSubject(ctx, tx, actor, action, node, task, "", status)
}
func auditSubject(ctx context.Context, tx *sql.Tx, actor, action, node, task, subject, status string) error {
	if _, e := tx.ExecContext(ctx, "INSERT INTO audit_events(timestamp,actor,action,node_id,task_id,subject_id,status) VALUES(?,?,?,?,?,?,?)", time.Now().Unix(), actor, action, node, task, subject, status); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, "DELETE FROM audit_events WHERE id <= (SELECT max(id)-? FROM audit_events)", AuditCapacity)
	return e
}

type AuditEvent struct {
	ID        int64  `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	NodeID    string `json:"node_id"`
	TaskID    string `json:"task_id"`
	Status    string `json:"status"`
}

func (s *Store) AuditEvents(ctx context.Context, after int64) ([]AuditEvent, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,timestamp,actor,action,node_id,task_id,status FROM audit_events WHERE id>? ORDER BY id LIMIT 200", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var v AuditEvent
		if e = rows.Scan(&v.ID, &v.Timestamp, &v.Actor, &v.Action, &v.NodeID, &v.TaskID, &v.Status); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) CreateToken(ctx context.Context, actor string, ttl time.Duration) (string, error) {
	if ttl < time.Minute || ttl > time.Hour {
		return "", errors.New("enrollment token lifetime must be 1-60 minutes")
	}
	token := identity.RandomID() + identity.RandomID()
	e := s.Write(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, "DELETE FROM enrollment_tokens WHERE expires_at<?", time.Now().Unix()); e != nil {
			return e
		}
		var count int
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM enrollment_tokens").Scan(&count); e != nil {
			return e
		}
		if count >= 1000 {
			return ErrConflict
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO enrollment_tokens(digest,expires_at) VALUES(?,?)", TokenDigest(token), time.Now().Add(ttl).Unix()); e != nil {
			return e
		}
		return Audit(ctx, tx, actor, "enrollment.create", "", "", "accepted")
	})
	return token, e
}
func Authorize(ctx context.Context, tx *sql.Tx, c *x509.Certificate) (string, error) {
	id, e := identity.FromCertificate(c)
	now := time.Now()
	if e != nil || now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
		return "", ErrUnauthorized
	}
	var fp, previous, status string
	var until int64
	if e = tx.QueryRowContext(ctx, "SELECT certificate_fingerprint,previous_fingerprint,previous_until,status FROM nodes WHERE id=?", id).Scan(&fp, &previous, &until, &status); e != nil {
		return "", ErrUnauthorized
	}
	got := identity.Fingerprint(c)
	if status != "active" || got != fp && (got != previous || now.Unix() >= until) {
		return "", ErrUnauthorized
	}
	return id, nil
}
func (s *Store) Authorize(ctx context.Context, c *x509.Certificate) (string, error) {
	var id string
	e := s.Write(ctx, func(tx *sql.Tx) error { var e error; id, e = Authorize(ctx, tx, c); return e })
	return id, e
}
func (s *Store) Nodes(ctx context.Context, after string) ([]protocol.Node, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,hostname,certificate_fingerprint,status,last_seen_at,created_at,certificate_expires_at,protocol_version,agent_version FROM nodes WHERE id>? ORDER BY id LIMIT 200", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []protocol.Node{}
	for rows.Next() {
		var n protocol.Node
		if e = rows.Scan(&n.ID, &n.Hostname, &n.CertificateFingerprint, &n.Status, &n.LastSeenAt, &n.CreatedAt, &n.CertificateExpiresAt, &n.ProtocolVersion, &n.AgentVersion); e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) Heartbeat(ctx context.Context, c *x509.Certificate, hostname string, metadata protocol.AgentMetadata) error {
	if hostname == "" || !protocol.CleanText(hostname, 255) || !metadata.Valid() {
		return errors.New("invalid hostname")
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		id, e := Authorize(ctx, tx, c)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, "UPDATE nodes SET hostname=?,last_seen_at=?,protocol_version=?,agent_version=? WHERE id=?", hostname, time.Now().Unix(), metadata.ProtocolVersion, metadata.AgentVersion, id)
		return e
	})
}
func (s *Store) Disable(ctx context.Context, actor, id string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		r, e := tx.ExecContext(ctx, "UPDATE nodes SET status='disabled' WHERE id=?", id)
		if e != nil {
			return e
		}
		n, e := r.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			return ErrNotFound
		}
		if e = finishOutstanding(ctx, tx, id, "node_disabled", s.now().Unix()); e != nil {
			return e
		}
		return Audit(ctx, tx, actor, "node.disable", id, "", "succeeded")
	})
}

// Backup reserves a private destination exclusively, includes committed WAL,
// verifies the snapshot, then syncs it. It never overwrites an existing file.
func (s *Store) Backup(ctx context.Context, path string) error {
	return s.backupVersion(ctx, path, SchemaVersion)
}
func (s *Store) backupVersion(ctx context.Context, path string, expectedVersion int) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	file, e := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer file.Close()
	if _, e = s.DB.ExecContext(ctx, "VACUUM INTO ?", abs); e != nil {
		return e
	}
	uriPath := filepath.ToSlash(abs)
	if runtime.GOOS == "windows" {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro"}
	snapshot, e := sql.Open("sqlite", uri.String())
	if e != nil {
		return e
	}
	defer snapshot.Close()
	var integrity string
	if e = snapshot.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); e != nil {
		return e
	}
	if integrity != "ok" {
		return errors.New("backup integrity check failed")
	}
	var version, component int
	if e = snapshot.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil {
		return e
	}
	if e = snapshot.QueryRowContext(ctx, "PRAGMA application_id").Scan(&component); e != nil {
		return e
	}
	if version != expectedVersion || component != applicationID {
		return errors.New("backup schema check failed")
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if runtime.GOOS != "windows" {
		dir, e := os.Open(filepath.Dir(abs))
		if e != nil {
			return e
		}
		defer dir.Close()
		return dir.Sync()
	}
	return nil
}
