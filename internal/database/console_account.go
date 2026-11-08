package database

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const localConsoleIssuer = "urn:argus:local"

var ErrOAuthRequired = errors.New("verified alternative login required")

func (s *Store) DisableConsoleToken(ctx context.Context, providerID, issuer string) error {
	a, ok := ctx.Value(consoleActorKey{}).(consoleActor)
	if !ok || !a.Admin {
		return ErrUnauthorized
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM console_identities i CROSS JOIN console_state s WHERE i.user_id=? AND i.issuer=? AND s.id=1 AND s.provider_id=?`, a.ID, issuer, providerID).Scan(&count); err != nil {
			return err
		}
		if count == 0 || providerID == "" {
			return ErrOAuthRequired
		}
		if _, err := tx.ExecContext(ctx, "UPDATE console_token SET digest='' WHERE id=1"); err != nil {
			return err
		}
		return auditSubject(ctx, tx, "web:"+a.ID, "console.token.disable", "", "", a.ID, "succeeded")
	})
}

// IssueConsoleToken is local-only. Recovery explicitly revokes sessions and
// replaces administrator access on the next successful token login.
func (s *Store) IssueConsoleToken(ctx context.Context, recovery bool) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(bytes)
	err := s.Write(ctx, func(tx *sql.Tx) error {
		state, err := scanConsoleState(tx.QueryRowContext(ctx, "SELECT "+consoleStateColumns+" FROM console_state WHERE id=1"))
		if err != nil {
			return err
		}
		if state.Initialized != recovery {
			return ErrSetupClosed
		}
		if _, err = tx.ExecContext(ctx, "UPDATE console_state SET recovery=?,generation=generation+1,bootstrap_digest='',bootstrap_expires=0,bootstrap_attempts=0 WHERE id=1", recovery); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO console_token(id,digest,generation) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET digest=excluded.digest,user_id='',generation=excluded.generation", TokenDigest(secret), state.Generation+1); err != nil {
			return err
		}
		return auditSubject(ctx, tx, "local", "console.token.issue", "", "", "", "succeeded")
	})
	return secret, err
}

func (s *Store) ConsoleTokenAvailable(ctx context.Context) (bool, error) {
	var count int
	err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM console_token t JOIN console_state s ON s.id=t.id AND s.generation=t.generation WHERE t.digest<>''`).Scan(&count)
	return count > 0, err
}

// Token login is independent of OAuth discovery and keeps the secret out of
// sessions. An unconsumed, unexpired legacy bootstrap code can be upgraded too.
func (s *Store) LoginConsoleToken(ctx context.Context, secret string) (ConsoleUser, int64, error) {
	var out ConsoleUser
	var generation int64
	if !identity.Hex(secret, 64) {
		return out, 0, ErrUnauthorized
	}
	err := s.Write(ctx, func(tx *sql.Tx) error {
		state, err := scanConsoleState(tx.QueryRowContext(ctx, "SELECT "+consoleStateColumns+" FROM console_state WHERE id=1"))
		if err != nil {
			return err
		}
		generation = state.Generation
		var digest, userID string
		var tokenGeneration int64
		err = tx.QueryRowContext(ctx, "SELECT digest,user_id,generation FROM console_token WHERE id=1").Scan(&digest, &userID, &tokenGeneration)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		valid := err == nil && tokenGeneration == generation && digest != "" && subtle.ConstantTimeCompare([]byte(digest), []byte(TokenDigest(secret))) == 1
		if !valid {
			if !state.SetupOpen(s.now().Unix()) || state.BootstrapAttempts >= 5 || state.BootstrapDigest == "" || subtle.ConstantTimeCompare([]byte(state.BootstrapDigest), []byte(TokenDigest(secret))) != 1 {
				return ErrUnauthorized
			}
			userID = ""
			if _, err = tx.ExecContext(ctx, "INSERT INTO console_token(id,digest,generation) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET digest=excluded.digest,user_id='',generation=excluded.generation", TokenDigest(secret), generation); err != nil {
				return err
			}
		}
		now := s.now().Unix()
		if userID == "" {
			if state.Initialized && !state.Recovery {
				return ErrUnauthorized
			}
			if state.Recovery {
				if _, err = tx.ExecContext(ctx, "UPDATE console_users SET status='disabled',version=version+1 WHERE role='Admin'"); err != nil {
					return err
				}
			}
			userID = identity.RandomID()
			if _, err = tx.ExecContext(ctx, "INSERT INTO console_users(id,name,issuer,subject,role,status,created_at,last_login_at) VALUES(?,'Administrator',?,?,'Admin','active',?,?)", userID, localConsoleIssuer, userID, now, now); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE console_token SET user_id=? WHERE id=1", userID); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE console_state SET initialized=1,recovery=0,bootstrap_digest='',bootstrap_expires=0 WHERE id=1"); err != nil {
				return err
			}
		} else if !state.Initialized || state.Recovery {
			return ErrUnauthorized
		}
		out, err = ScanConsoleUser(tx.QueryRowContext(ctx, "SELECT "+consoleUserColumns+" FROM console_users WHERE id=?", userID))
		if err != nil {
			return err
		}
		if out.Status != "active" || out.Role != "Admin" {
			return ErrUnauthorized
		}
		if _, err = tx.ExecContext(ctx, "UPDATE console_users SET last_login_at=? WHERE id=?", now, userID); err != nil {
			return err
		}
		return auditSubject(ctx, tx, "web:"+userID, "console.token.login", "", "", userID, "succeeded")
	})
	return out, generation, err
}

type ConsoleIdentity struct {
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) ConsoleIdentities(ctx context.Context, userID string) ([]ConsoleIdentity, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT issuer,subject,created_at FROM console_identities WHERE user_id=? ORDER BY issuer,subject", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ConsoleIdentity{}
	for rows.Next() {
		var item ConsoleIdentity
		if err := rows.Scan(&item.Issuer, &item.Subject, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) BindConsoleIdentity(ctx context.Context, userID string, version, generation int64, providerID, issuer, subject string) error {
	if subject == "" || !protocol.CleanText(subject, 255) || !protocol.CleanText(issuer, 2048) {
		return ErrUnauthorized
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM console_users u CROSS JOIN console_state s WHERE u.id=? AND u.version=? AND u.status='active' AND s.initialized=1 AND s.recovery=0 AND s.generation=? AND s.provider_id=?`, userID, version, generation, providerID).Scan(&count); err != nil {
			return err
		}
		if count != 1 || providerID == "" {
			return ErrUnauthorized
		}
		var existing string
		err := tx.QueryRowContext(ctx, "SELECT user_id FROM console_identities WHERE issuer=? AND subject=?", issuer, subject).Scan(&existing)
		if err == nil && existing != userID {
			return ErrConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO console_identities(issuer,subject,user_id,created_at) VALUES(?,?,?,?) ON CONFLICT(issuer,subject) DO NOTHING", issuer, subject, userID, s.now().Unix()); err != nil {
			return err
		}
		return auditSubject(ctx, tx, "web:"+userID, "console.identity.bind", "", "", userID, "succeeded")
	})
}

// The authenticated actor is checked inside Write; expected snapshots reject
// concurrent configuration edits and stale login/binding transactions.
func (s *Store) ConfigureConsoleProvider(ctx context.Context, generation int64, previousID, providerID string, issuers ...string) error {
	a, ok := ctx.Value(consoleActorKey{}).(consoleActor)
	if !ok || !a.Admin {
		return ErrUnauthorized
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		var tokenCount int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM console_token WHERE digest<>'' AND generation=?", generation).Scan(&tokenCount); err != nil {
			return err
		}
		if tokenCount == 0 {
			linked := false
			for _, issuer := range issuers {
				var count int
				if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM console_identities WHERE user_id=? AND issuer=?", a.ID, issuer).Scan(&count); err != nil {
					return err
				}
				linked = linked || count > 0
			}
			if !linked {
				return ErrOAuthRequired
			}
		}
		result, err := tx.ExecContext(ctx, "UPDATE console_state SET provider_id=? WHERE id=1 AND initialized=1 AND recovery=0 AND generation=? AND provider_id=?", providerID, generation, previousID)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return ErrConflict
		}
		return auditSubject(ctx, tx, "web:"+a.ID, "console.provider.configure", "", "", "", "succeeded")
	})
}
