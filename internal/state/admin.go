package state

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
)

var ErrAdminUnauthorized = errors.New("invalid administrator credentials or session")
var ErrAdminForbidden = errors.New("administrator role required")
var ErrAdminLimited = errors.New("administrator request limit reached")
var ErrAdminUnavailable = errors.New("administrator state unavailable")

const SessionIdle = 30 * time.Minute
const SessionLifetime = 8 * time.Hour
const MaxUsers = 32
const MaxSessions = 128

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Enabled  bool   `json:"enabled"`
}
type Login struct {
	Token       string `json:"token"`
	User        User   `json:"user"`
	ExpiresAt   int64  `json:"expires_at"`
	IdleSeconds int64  `json:"idle_seconds"`
}
type session struct {
	User      User
	ID, Hash  string
	ExpiresAt int64
}

func migrateAdmins(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `CREATE TABLE admin_users(
 id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,role TEXT NOT NULL CHECK(role IN ('Admin','ReadOnly')),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),password_hash TEXT NOT NULL,generation INTEGER NOT NULL);
CREATE TABLE admin_sessions(
 token_hash TEXT PRIMARY KEY,id TEXT NOT NULL UNIQUE,user_id TEXT NOT NULL REFERENCES admin_users(id),
 created_at INTEGER NOT NULL,last_used INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE admin_limits(bucket TEXT PRIMARY KEY,started_at INTEGER NOT NULL,count INTEGER NOT NULL);
CREATE TABLE admin_clock(id INTEGER PRIMARY KEY CHECK(id=1),high INTEGER NOT NULL);
INSERT INTO admin_clock VALUES(1,0);
PRAGMA user_version=3;`)
	if err != nil {
		return err
	}
	return audit.Append(ctx, tx, audit.Event{Kind: "state_migrated", ActorID: "local-operator", Source: "local", Status: "succeeded", Code: "server_schema_3"}, 0)
}
func sessionHash(token string) (string, error) {
	if !identity.Hex(token, 64) {
		return "", ErrAdminUnauthorized
	}
	return audit.Digest([]byte("argus-c2/admin-session/v1\x00" + token)), nil
}
func adminClock(ctx context.Context, tx *sql.Tx, now int64) error {
	var high int64
	if err := tx.QueryRowContext(ctx, "SELECT high FROM admin_clock WHERE id=1").Scan(&high); err != nil {
		return err
	}
	if now < 1 || now < high-30 {
		return ErrAdminUnavailable
	}
	_, err := tx.ExecContext(ctx, "UPDATE admin_clock SET high=MAX(high,?) WHERE id=1", now)
	return err
}

// Limit state survives process restarts. Empty/expired buckets are pruned and
// unknown user names cannot create an unbounded database or audit stream.
func admitLogin(ctx context.Context, tx *sql.Tx, name, source string, now int64) (bool, bool, error) {
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_limits WHERE started_at<=?", now-60); err != nil {
		return false, false, err
	}
	allowed, firstBlock := true, false
	for _, b := range []struct {
		key   string
		limit int
	}{{"global", 30}, {"ip:" + audit.Digest([]byte(source)), 10}, {"name:" + name, 5}} {
		var started int64
		var count int
		err := tx.QueryRowContext(ctx, "SELECT started_at,count FROM admin_limits WHERE bucket=?", b.key).Scan(&started, &count)
		if errors.Is(err, sql.ErrNoRows) {
			var total int
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_limits").Scan(&total); err != nil {
				return false, false, err
			}
			if total >= 1024 {
				return false, false, ErrAdminLimited
			}
			started = now
		} else if err != nil {
			return false, false, err
		}
		if count >= b.limit {
			allowed = false
			if count == b.limit {
				firstBlock = true
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO admin_limits VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET count=excluded.count", b.key, started, min(count+1, b.limit+1)); err != nil {
			return false, false, err
		}
	}
	return allowed, firstBlock, nil
}
func revokeSessionTx(ctx context.Context, tx *sql.Tx, id, user, actor, source, kind string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE id=?", id); err != nil {
		return err
	}
	return audit.Append(ctx, tx, audit.Event{Kind: kind, ActorID: actor, Source: source, Status: "succeeded", Code: id}, -1)
}
func expireSessionsTx(ctx context.Context, tx *sql.Tx, now int64) error {
	rows, err := tx.QueryContext(ctx, "SELECT id,user_id FROM admin_sessions WHERE expires_at<=? OR last_used<=?", now, now-int64(SessionIdle/time.Second))
	if err != nil {
		return err
	}
	type item struct{ id, user string }
	var items []item
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.user); err != nil {
			rows.Close()
			return err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range items {
		if err := revokeSessionTx(ctx, tx, v.id, v.user, v.user, "server", "session_expired"); err != nil {
			return err
		}
	}
	return nil
}
func revokeUserSessionsTx(ctx context.Context, tx *sql.Tx, user, actor, source string) error {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM admin_sessions WHERE user_id=?", user)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := revokeSessionTx(ctx, tx, id, user, actor, source, "session_revoked"); err != nil {
			return err
		}
	}
	return nil
}

// Login consumes a durable rate budget and records an attempt before its KDF.
// It rechecks the exact credential generation after hashing, so concurrent local
// role/password/disable changes cannot issue a session from stale authority.
func (s *Store) Login(ctx context.Context, name, password, source string) (Login, error) {
	if !adminauth.Username(name) || !adminauth.PasswordInput(password) {
		return Login{}, ErrAdminUnauthorized
	}
	release, err := adminauth.Acquire(ctx)
	if err != nil {
		return Login{}, ErrAdminLimited
	}
	defer release()
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Login{}, err
	}
	defer tx.Rollback()
	if err := adminClock(ctx, tx, now); err != nil {
		return Login{}, err
	}
	allowed, first, err := admitLogin(ctx, tx, name, source, now)
	if err != nil {
		return Login{}, err
	}
	if !allowed {
		if first {
			if err := audit.Append(ctx, tx, audit.Event{Kind: "login_limited", Source: source, Status: "rejected", Code: "rate_limited"}, 0); err != nil {
				return Login{}, err
			}
		}
		if err := tx.Commit(); err != nil {
			return Login{}, err
		}
		return Login{}, ErrAdminLimited
	}
	var u User
	var encoded string
	var generation int64
	err = tx.QueryRowContext(ctx, "SELECT id,username,role,enabled,password_hash,generation FROM admin_users WHERE username=?", name).Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &encoded, &generation)
	known := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		encoded = adminauth.Dummy()
	} else if err != nil {
		return Login{}, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "login_attempt", Source: source, Status: "accepted"}, 0); err != nil {
		return Login{}, err
	}
	if err := tx.Commit(); err != nil {
		return Login{}, err
	}
	match, err := s.verifyPassword(password, encoded)
	if err != nil {
		return Login{}, ErrAdminUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Login{}, err
	}
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		return Login{}, err
	}
	defer tx.Rollback()
	now = time.Now().Unix()
	if err := adminClock(ctx, tx, now); err != nil {
		return Login{}, err
	}
	var live int
	if known {
		err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_users WHERE id=? AND enabled=1 AND generation=? AND password_hash=? AND role=?", u.ID, generation, encoded, u.Role).Scan(&live)
		if err != nil {
			return Login{}, err
		}
	}
	if !match || !known || !u.Enabled || live != 1 {
		if err := audit.Append(ctx, tx, audit.Event{Kind: "login_failed", Source: source, Status: "rejected", Code: "credentials"}, 0); err != nil {
			return Login{}, err
		}
		if err := tx.Commit(); err != nil {
			return Login{}, err
		}
		return Login{}, ErrAdminUnauthorized
	}
	if err := expireSessionsTx(ctx, tx, now); err != nil {
		return Login{}, err
	}
	var total, owned int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE user_id WHEN ? THEN 1 ELSE 0 END),0) FROM admin_sessions", u.ID).Scan(&total, &owned); err != nil {
		return Login{}, err
	}
	if total >= MaxSessions || owned >= 8 {
		if err := audit.Append(ctx, tx, audit.Event{Kind: "login_failed", ActorID: u.ID, Source: source, Status: "rejected", Code: "session_limit"}, 0); err != nil {
			return Login{}, err
		}
		if err := tx.Commit(); err != nil {
			return Login{}, err
		}
		return Login{}, ErrAdminLimited
	}
	token := identity.RandomID() + identity.RandomID()
	hash, _ := sessionHash(token)
	id := identity.RandomID()
	expires := now + int64(SessionLifetime/time.Second)
	if _, err := tx.ExecContext(ctx, "INSERT INTO admin_sessions VALUES(?,?,?,?,?,?)", hash, id, u.ID, now, now, expires); err != nil {
		return Login{}, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "login_succeeded", ActorID: u.ID, Source: source, Status: "succeeded", Code: id}, 1); err != nil {
		return Login{}, err
	}
	if err := tx.Commit(); err != nil {
		return Login{}, err
	}
	return Login{Token: token, User: u, ExpiresAt: expires, IdleSeconds: int64(SessionIdle / time.Second)}, nil
}

func authorizeAdminTx(ctx context.Context, tx *sql.Tx, token string, now int64) (session, error) {
	hash, err := sessionHash(token)
	if err != nil {
		return session{}, err
	}
	var v session
	v.Hash = hash
	err = tx.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.enabled,s.id,s.expires_at FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id
 WHERE s.token_hash=? AND u.enabled=1 AND s.expires_at>? AND s.last_used>? AND s.created_at<=?`, hash, now, now-int64(SessionIdle/time.Second), now+30).Scan(&v.User.ID, &v.User.Username, &v.User.Role, &v.User.Enabled, &v.ID, &v.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return session{}, ErrAdminUnauthorized
	}
	if err != nil {
		return session{}, err
	}
	if !adminauth.Role(v.User.Role) || !identity.Hex(v.User.ID, 32) {
		return session{}, ErrAdminUnavailable
	}
	return v, nil
}

// Local account administration is deliberately separate from the HTTP API.
// User names and IDs are immutable; no account is silently re-enabled.
func (s *Store) CreateUser(ctx context.Context, name, role, password string) (User, error) {
	if !adminauth.Username(name) || !adminauth.Role(role) {
		return User{}, errors.New("invalid user name or role")
	}
	release, err := adminauth.Acquire(ctx)
	if err != nil {
		return User{}, err
	}
	defer release()
	encoded, err := adminauth.Hash(password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_users").Scan(&count); err != nil {
		return User{}, err
	}
	if count >= MaxUsers || count == 0 && role != adminauth.Admin {
		return User{}, errors.New("user limit reached or first account is not Admin")
	}
	u := User{ID: identity.RandomID(), Username: name, Role: role, Enabled: true}
	if _, err := tx.ExecContext(ctx, "INSERT INTO admin_users VALUES(?,?,?,?,?,1)", u.ID, u.Username, u.Role, true, encoded); err != nil {
		return User{}, errors.New("could not create user")
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "user_created_" + role, ActorID: "local-operator", Source: "local", Status: "succeeded", Code: u.ID}, 0); err != nil {
		return User{}, err
	}
	return u, tx.Commit()
}
func (s *Store) ChangeUser(ctx context.Context, name, action, value string) error {
	if !adminauth.Username(name) {
		return errors.New("invalid user name")
	}
	switch action {
	case "password":
		release, err := adminauth.Acquire(ctx)
		if err != nil {
			return err
		}
		defer release()
		encoded, err := adminauth.Hash(value)
		if err != nil {
			return err
		}
		value = encoded
	case "role":
		if !adminauth.Role(value) {
			return errors.New("invalid role")
		}
	case "disable", "revoke":
		if value != "" {
			return errors.New("unexpected account value")
		}
	default:
		return errors.New("unknown user action")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id string
	var enabled bool
	if err := tx.QueryRowContext(ctx, "SELECT id,enabled FROM admin_users WHERE username=?", name).Scan(&id, &enabled); err != nil {
		return errors.New("user not found")
	}
	if !enabled && action != "revoke" {
		return errors.New("user is disabled")
	}
	// One account-change event records aggregate revocation, consuming its
	// sessions' reserved slots. This still works at full audit capacity.
	var revoked int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_sessions WHERE user_id=?", id).Scan(&revoked); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE user_id=?", id); err != nil {
		return err
	}
	kind := "user_" + action
	switch action {
	case "password":
		_, err = tx.ExecContext(ctx, "UPDATE admin_users SET password_hash=?,generation=generation+1 WHERE id=?", value, id)
	case "role":
		_, err = tx.ExecContext(ctx, "UPDATE admin_users SET role=?,generation=generation+1 WHERE id=?", value, id)
		kind += "_" + value
	case "disable":
		_, err = tx.ExecContext(ctx, "UPDATE admin_users SET enabled=0,generation=generation+1 WHERE id=?", id)
	case "revoke":
		_, err = tx.ExecContext(ctx, "UPDATE admin_users SET generation=generation+1 WHERE id=?", id)
	}
	if err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: kind, ActorID: "local-operator", Source: "local", Status: "succeeded", Code: id}, -revoked); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Users(ctx context.Context) ([]User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id,username,role,enabled FROM admin_users ORDER BY username LIMIT ?", MaxUsers)
	if err != nil {
		return nil, err
	}
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled); err != nil {
			rows.Close()
			return nil, err
		}
		users = append(users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "users_read", ActorID: "local-operator", Source: "local", Status: "succeeded"}, 0); err != nil {
		return nil, err
	}
	return users, tx.Commit()
}

// RevokeAllSessions is a local recovery operation, including after a restored
// backup. It also invalidates password checks already in progress.
func (s *Store) RevokeAllSessions(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_sessions").Scan(&count); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions; UPDATE admin_users SET generation=generation+1;"); err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "all_sessions_revoked", ActorID: "local-operator", Source: "local", Status: "succeeded"}, -count); err != nil {
		return err
	}
	return tx.Commit()
}
