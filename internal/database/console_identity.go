package database

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

var ErrSetupClosed = errors.New("console setup closed")
var ErrBootstrapInvalid = errors.New("bootstrap proof invalid")
var ErrLastAdmin = errors.New("last active console administrator")
var ErrSelfChange = errors.New("cannot change own console access")

type ConsoleState struct {
	Initialized       bool
	Recovery          bool
	Generation        int64
	BootstrapDigest   string
	BootstrapExpires  int64
	BootstrapAttempts int
	ProviderID        string
}

const consoleStateColumns = "initialized,recovery,generation,bootstrap_digest,bootstrap_expires,bootstrap_attempts,provider_id"

func scanConsoleState(row scanner) (ConsoleState, error) {
	var v ConsoleState
	err := row.Scan(&v.Initialized, &v.Recovery, &v.Generation, &v.BootstrapDigest, &v.BootstrapExpires, &v.BootstrapAttempts, &v.ProviderID)
	return v, err
}
func (s *Store) ConsoleState(ctx context.Context) (ConsoleState, error) {
	return scanConsoleState(s.DB.QueryRowContext(ctx, "SELECT "+consoleStateColumns+" FROM console_state WHERE id=1"))
}
func (v ConsoleState) SetupOpen(now int64) bool {
	return (!v.Initialized || v.Recovery) && v.BootstrapExpires > now
}

// Web access is checked again inside the same transaction as each mutation,
// including shared Fleet services. Local recovery/role changes cannot race a
// previously authorized browser request into performing a new write.
type consoleActorKey struct{}
type consoleActor struct {
	ID                  string
	Version, Generation int64
	Admin               bool
}

func WithConsoleActor(ctx context.Context, id string, version, generation int64, admin bool) context.Context {
	return context.WithValue(ctx, consoleActorKey{}, consoleActor{id, version, generation, admin})
}
func authorizeConsoleContext(ctx context.Context, tx *sql.Tx) error {
	a, ok := ctx.Value(consoleActorKey{}).(consoleActor)
	if !ok {
		return nil
	}
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM console_users u CROSS JOIN console_state s
 WHERE u.id=? AND u.version=? AND u.status='active' AND s.id=1 AND s.initialized=1
 AND s.generation=? AND (?=0 OR u.role='Admin')`, a.ID, a.Version, a.Generation, a.Admin).Scan(&n)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrUnauthorized
	}
	return nil
}

// IssueConsoleBootstrap is local-only. Explicit recovery revokes existing
// sessions by advancing the generation, but retains accounts until binding.
func (s *Store) IssueConsoleBootstrap(ctx context.Context, recovery bool) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(b)
	err := s.Write(ctx, func(tx *sql.Tx) error {
		state, err := scanConsoleState(tx.QueryRowContext(ctx, "SELECT "+consoleStateColumns+" FROM console_state WHERE id=1"))
		if err != nil {
			return err
		}
		if state.Initialized && !recovery || !state.Initialized && recovery {
			return ErrSetupClosed
		}
		_, err = tx.ExecContext(ctx, `UPDATE console_state SET recovery=?,generation=generation+1,bootstrap_digest=?,bootstrap_expires=?,bootstrap_attempts=0 WHERE id=1`, recovery, TokenDigest(secret), s.now().Add(15*time.Minute).Unix())
		if err != nil {
			return err
		}
		action := "console.bootstrap.issue"
		if recovery {
			action = "console.recovery.issue"
		}
		return auditSubject(ctx, tx, "local", action, "", "", "", "succeeded")
	})
	if err != nil {
		return "", err
	}
	return secret, nil
}

// The valid proof is consumed once; unsuccessful attempts are committed too.
func (s *Store) ProveConsoleBootstrap(ctx context.Context, secret string) (ConsoleState, error) {
	var out ConsoleState
	valid := false
	err := s.Write(ctx, func(tx *sql.Tx) error {
		state, err := scanConsoleState(tx.QueryRowContext(ctx, "SELECT "+consoleStateColumns+" FROM console_state WHERE id=1"))
		if err != nil {
			return err
		}
		if state.Initialized && !state.Recovery {
			return ErrSetupClosed
		}
		if !state.SetupOpen(s.now().Unix()) || state.BootstrapAttempts >= 5 || state.BootstrapDigest == "" {
			return nil
		}
		valid = identity.Hex(secret, 64) && subtle.ConstantTimeCompare([]byte(state.BootstrapDigest), []byte(TokenDigest(secret))) == 1
		if valid {
			_, err = tx.ExecContext(ctx, "UPDATE console_state SET bootstrap_digest='' WHERE id=1")
			out = state
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE console_state SET bootstrap_attempts=bootstrap_attempts+1 WHERE id=1")
		}
		if err != nil {
			return err
		}
		status := "denied"
		if valid {
			status = "succeeded"
		}
		return auditSubject(ctx, tx, "setup", "console.bootstrap.prove", "", "", "", status)
	})
	if err != nil {
		return out, err
	}
	if !valid {
		return out, ErrBootstrapInvalid
	}
	return out, nil
}
func (s *Store) SetConsoleProvider(ctx context.Context, generation int64, providerID string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		state, err := scanConsoleState(tx.QueryRowContext(ctx, "SELECT "+consoleStateColumns+" FROM console_state WHERE id=1"))
		if err != nil {
			return err
		}
		if !state.SetupOpen(s.now().Unix()) || state.Generation != generation {
			return ErrSetupClosed
		}
		if _, err = tx.ExecContext(ctx, "UPDATE console_state SET provider_id=? WHERE id=1", providerID); err != nil {
			return err
		}
		return auditSubject(ctx, tx, "setup", "console.provider.configure", "", "", "", "succeeded")
	})
}

type ConsoleUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	LastLoginAt *int64 `json:"last_login_at"`
	Version     int64  `json:"version"`
}

const consoleUserColumns = "id,name,issuer,subject,role,status,created_at,last_login_at,version"

func ScanConsoleUser(row interface{ Scan(...any) error }) (ConsoleUser, error) {
	var u ConsoleUser
	err := row.Scan(&u.ID, &u.Name, &u.Issuer, &u.Subject, &u.Role, &u.Status, &u.CreatedAt, &u.LastLoginAt, &u.Version)
	return u, err
}
func (s *Store) ConsoleUser(ctx context.Context, id string) (ConsoleUser, error) {
	u, err := ScanConsoleUser(s.DB.QueryRowContext(ctx, "SELECT "+consoleUserColumns+" FROM console_users WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return u, err
}

// Called only after verified OIDC claims or a trusted OAuth provider's identity
// response. Binding, account state,
// permanent initialization and audit all commit together.
func (s *Store) FinishConsoleLogin(ctx context.Context, generation int64, providerID, issuer, subject, name string, setup bool) (ConsoleUser, error) {
	var out ConsoleUser
	if subject == "" || !protocol.CleanText(subject, 255) || !protocol.CleanText(issuer, 2048) {
		return out, ErrUnauthorized
	}
	if name == "" || !protocol.CleanText(name, 128) {
		name = "Console user"
	}
	err := s.Write(ctx, func(tx *sql.Tx) error {
		state, err := scanConsoleState(tx.QueryRowContext(ctx, "SELECT "+consoleStateColumns+" FROM console_state WHERE id=1"))
		if err != nil {
			return err
		}
		if state.Generation != generation || state.ProviderID != providerID || providerID == "" {
			return ErrUnauthorized
		}
		// Multiple verified provider identities can belong to the same account.
		originalIssuer, originalSubject := issuer, subject
		var linkedIssuer, linkedSubject string
		err = tx.QueryRowContext(ctx, `SELECT u.issuer,u.subject FROM console_identities i JOIN console_users u ON u.id=i.user_id WHERE i.issuer=? AND i.subject=?`, issuer, subject).Scan(&linkedIssuer, &linkedSubject)
		if err == nil {
			issuer, subject = linkedIssuer, linkedSubject
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := s.now().Unix()
		if setup {
			if !state.SetupOpen(now) {
				return ErrSetupClosed
			}
			if state.Recovery {
				if _, err = tx.ExecContext(ctx, "UPDATE console_users SET status='disabled',version=version+1 WHERE role='Admin'"); err != nil {
					return err
				}
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO console_users(id,name,issuer,subject,role,status,created_at,last_login_at) VALUES(?,?,?,?,'Admin','active',?,?)
 ON CONFLICT(issuer,subject) DO UPDATE SET name=excluded.name,role='Admin',status='active',version=console_users.version+1,last_login_at=excluded.last_login_at`, identity.RandomID(), name, issuer, subject, now, now)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE console_state SET initialized=1,recovery=0,bootstrap_digest='',bootstrap_expires=0 WHERE id=1"); err != nil {
				return err
			}
		} else {
			if !state.Initialized || state.Recovery {
				return ErrUnauthorized
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM console_users WHERE status='pending' AND created_at<?", now-7*86400); err != nil {
				return err
			}
			var existing, count int
			if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM console_users WHERE issuer=? AND subject=?", issuer, subject).Scan(&existing); err != nil {
				return err
			}
			if existing == 0 {
				if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM console_users").Scan(&count); err != nil {
					return err
				}
				if count >= 1000 {
					return ErrConflict
				}
				_, err = tx.ExecContext(ctx, "INSERT INTO console_users(id,name,issuer,subject,role,status,created_at) VALUES(?,?,?,?,'User','pending',?)", identity.RandomID(), name, issuer, subject, now)
			} else {
				_, err = tx.ExecContext(ctx, "UPDATE console_users SET last_login_at=? WHERE issuer=? AND subject=? AND status='active'", now, issuer, subject)
			}
			if err != nil {
				return err
			}
		}
		out, err = ScanConsoleUser(tx.QueryRowContext(ctx, "SELECT "+consoleUserColumns+" FROM console_users WHERE issuer=? AND subject=?", issuer, subject))
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO console_identities(issuer,subject,user_id,created_at) VALUES(?,?,?,?) ON CONFLICT(issuer,subject) DO NOTHING", originalIssuer, originalSubject, out.ID, now); err != nil {
			return err
		}
		action := "console.login"
		if setup {
			action = "console.owner.bind"
		}
		if setup && state.Recovery {
			action = "console.owner.recover"
		}
		return auditSubject(ctx, tx, "web:"+out.ID, action, "", "", out.ID, out.Status)
	})
	return out, err
}

func (s *Store) UpdateConsoleUser(ctx context.Context, actor, id, role, status, confirm string, version int64) (ConsoleUser, error) {
	var out ConsoleUser
	if role != "Admin" && role != "User" || status != "active" && status != "disabled" || version < 1 {
		return out, ErrConflict
	}
	err := s.Write(ctx, func(tx *sql.Tx) error {
		u, err := ScanConsoleUser(tx.QueryRowContext(ctx, "SELECT "+consoleUserColumns+" FROM console_users WHERE id=?", id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if u.Version != version || u.Subject != confirm {
			return ErrConflict
		}
		if u.Role == "Admin" && u.Status == "active" && (role != "Admin" || status != "active") {
			var n int
			if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM console_users WHERE role='Admin' AND status='active'").Scan(&n); err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastAdmin
			}
		}
		if actor == id {
			return ErrSelfChange
		}
		if _, err = tx.ExecContext(ctx, "UPDATE console_users SET role=?,status=?,version=version+1 WHERE id=?", role, status, id); err != nil {
			return err
		}
		if err = auditSubject(ctx, tx, "web:"+actor, "console.user.update", "", "", id, role+":"+status); err != nil {
			return err
		}
		out = u
		out.Role = role
		out.Status = status
		out.Version++
		return nil
	})
	return out, err
}
func (s *Store) RevokeConsoleSessions(ctx context.Context, actor, id string) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		if err := updateOne(ctx, tx, "UPDATE console_users SET version=version+1 WHERE id=?", id); err != nil {
			return err
		}
		return auditSubject(ctx, tx, "web:"+actor, "console.sessions.revoke", "", "", id, "succeeded")
	})
}
func (s *Store) ConsoleAudit(ctx context.Context, actor, action, subject, status string) error {
	return s.Write(ctx, func(tx *sql.Tx) error { return auditSubject(ctx, tx, actor, action, "", "", subject, status) })
}
