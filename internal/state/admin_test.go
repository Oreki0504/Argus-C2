package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const adminPassword = "correct horse battery staple"

func TestSchemaTwoUpgradePreservesDispatchAndAudit(t *testing.T) {
	s, dir, bundle, key := taskStore(t)
	dispatched := enqueue(t, s, bundle.Node.AgentID)
	envelope, err := s.Poll(t.Context(), bundle.Probe.Leaf, dispatched.PolicyDigest, key, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	queued := enqueue(t, s, bundle.Node.AgentID)
	var sequence int64
	var hash string
	if err := s.db.QueryRow("SELECT sequence,hash FROM audit_head WHERE id=1").Scan(&sequence, &hash); err != nil {
		t.Fatal(err)
	}
	// Remove only the empty administration tables to reproduce the schema-2
	// boundary while retaining real enrolled identity, task, and audit state.
	if _, err := s.db.Exec(`DROP TABLE admin_sessions; DROP TABLE admin_users;
DROP TABLE admin_limits; DROP TABLE admin_clock; PRAGMA user_version=2;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version, reserved int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 3 {
		t.Fatal("wrong migrated schema", version, err)
	}
	if err := s.db.QueryRow("SELECT reserved FROM audit_head WHERE id=1").Scan(&reserved); err != nil || reserved != 4 {
		t.Fatal("lost task or node reservations", reserved, err)
	}
	var oldHash, previous string
	if err := s.db.QueryRow("SELECT hash FROM audit_events WHERE sequence=?", sequence).Scan(&oldHash); err != nil || oldHash != hash {
		t.Fatal("upgrade rewrote existing audit", err)
	}
	if err := s.db.QueryRow("SELECT previous_hash FROM audit_events WHERE sequence=?", sequence+1).Scan(&previous); err != nil || previous != hash {
		t.Fatal("upgrade broke audit continuity", err)
	}
	if err := s.ConfigureSigner(t.Context(), key); err != nil {
		t.Fatal("upgrade lost signing-key pin", err)
	}
	retry, err := s.Poll(t.Context(), bundle.Probe.Leaf, dispatched.PolicyDigest, key, "127.0.0.1")
	if err != nil || !bytes.Equal(retry, envelope) {
		t.Fatal("upgrade changed dispatched envelope or node authorization", err)
	}
	rows, err := s.Tasks(t.Context(), 0, 10)
	if err != nil || len(rows) != 2 || rows[1].Task.RequestID != queued.RequestID || rows[1].State != "queued" {
		t.Fatal("upgrade changed queued work", err)
	}
	account(t, s, "operator", adminauth.Admin)
	if err := me(t, s, login(t, s, "operator").Token); err != nil {
		t.Fatal("new authentication unavailable after upgrade", err)
	}
}

func TestInFlightLoginCannotSurviveAuthorityChange(t *testing.T) {
	s, _ := openTest(t)
	account(t, s, "operator", adminauth.Admin)
	entered, release := make(chan struct{}), make(chan struct{})
	s.verifyPassword = func(password, encoded string) (bool, error) {
		close(entered)
		<-release
		return adminauth.Verify(password, encoded)
	}
	done := make(chan error, 1)
	go func() { _, err := s.Login(t.Context(), "operator", adminPassword, "127.0.0.1"); done <- err }()
	<-entered
	err := s.ChangeUser(t.Context(), "operator", "role", adminauth.ReadOnly)
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrAdminUnauthorized) {
		t.Fatal("in-flight login used stale authority", err)
	}
}

func account(t *testing.T, s *Store, name, role string) User {
	t.Helper()
	u, err := s.CreateUser(t.Context(), name, role, adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func login(t *testing.T, s *Store, name string) Login {
	t.Helper()
	v, err := s.Login(t.Context(), name, adminPassword, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func me(t *testing.T, s *Store, token string) error {
	t.Helper()
	_, err := s.Manage(t.Context(), token, "127.0.0.1", ManagementRequest{Operation: "whoami"})
	return err
}
func TestAdminRolesAndAtomicTaskAudit(t *testing.T) {
	s, _, bundle, _ := taskStore(t)
	admin := account(t, s, "operator", adminauth.Admin)
	account(t, s, "viewer", adminauth.ReadOnly)
	a, v := login(t, s, "operator"), login(t, s, "viewer")
	requests := []ManagementRequest{
		{Operation: "submit", AgentID: bundle.Node.AgentID, Type: protocol.SystemInfo, Params: json.RawMessage(`{}`), TTLSeconds: 60},
		{Operation: "token", TTLSeconds: 60}, {Operation: "disable", AgentID: bundle.Node.AgentID},
	}
	for _, r := range requests {
		if _, err := s.Manage(t.Context(), v.Token, "127.0.0.1", r); !errors.Is(err, ErrAdminForbidden) {
			t.Fatal("ReadOnly mutated state", err)
		}
	}
	for _, r := range []ManagementRequest{{Operation: "agents", Limit: 50}, {Operation: "tasks", Limit: 50}, {Operation: "audit", Limit: 50}} {
		if _, err := s.Manage(t.Context(), v.Token, "127.0.0.1", r); err != nil {
			t.Fatal("ReadOnly query denied", err)
		}
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&count)
	if count != 0 {
		t.Fatal("query dispatched a task")
	}
	if _, err := s.db.Exec("CREATE TRIGGER deny_task_audit BEFORE INSERT ON audit_events WHEN NEW.kind='task_queued' BEGIN SELECT RAISE(ABORT,'disk failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Manage(t.Context(), a.Token, "127.0.0.1", requests[0]); err == nil {
		t.Fatal("unaudited task admitted")
	}
	s.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&count)
	if count != 0 {
		t.Fatal("partial task commit")
	}
	if _, err := s.db.Exec("DROP TRIGGER deny_task_audit"); err != nil {
		t.Fatal(err)
	}
	result, err := s.Manage(t.Context(), a.Token, "127.0.0.2", requests[0])
	if err != nil {
		t.Fatal(err)
	}
	task := result.(protocol.Task)
	if task.ActorID != admin.ID {
		t.Fatal("task actor not derived from session")
	}
	page, err := s.Audit(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range page.Records {
		if r.Event.Kind == "task_queued" {
			found = true
			if r.Event.ActorID != admin.ID || r.Event.Source != "127.0.0.2" {
				t.Fatal("lost authenticated provenance")
			}
		}
	}
	if !found {
		t.Fatal("missing task audit")
	}
	b, _ := json.Marshal(page)
	if strings.Contains(string(b), a.Token) || strings.Contains(string(b), adminPassword) {
		t.Fatal("secret in audit")
	}
}
func TestAccountChangesRevokeAllSessions(t *testing.T) {
	for _, action := range []string{"password", "role", "disable", "revoke"} {
		t.Run(action, func(t *testing.T) {
			s, dir := openTest(t)
			account(t, s, "operator", adminauth.Admin)
			a, b := login(t, s, "operator"), login(t, s, "operator")
			value := ""
			if action == "password" {
				value = "another long passphrase here"
			}
			if action == "role" {
				value = adminauth.ReadOnly
			}
			if err := s.ChangeUser(t.Context(), "operator", action, value); err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{a.Token, b.Token} {
				if err := me(t, s, token); !errors.Is(err, ErrAdminUnauthorized) {
					t.Fatal("old session survived", err)
				}
			}
			s.Close()
			reopened, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if err := me(t, reopened, a.Token); !errors.Is(err, ErrAdminUnauthorized) {
				t.Fatal("restart revived revoked session", err)
			}
			if action == "password" || action == "disable" {
				if _, err := reopened.Login(t.Context(), "operator", adminPassword, "127.0.0.1"); !errors.Is(err, ErrAdminUnauthorized) {
					t.Fatal("old credential remained valid", err)
				}
			}
		})
	}
}
func TestSessionStorageExpiryAndLogout(t *testing.T) {
	for _, scenario := range []string{"logout", "idle", "absolute", "clock"} {
		t.Run(scenario, func(t *testing.T) {
			s, dir := openTest(t)
			account(t, s, "operator", adminauth.Admin)
			a := login(t, s, "operator")
			var hash, passwordHash string
			s.db.QueryRow("SELECT token_hash FROM admin_sessions").Scan(&hash)
			s.db.QueryRow("SELECT password_hash FROM admin_users").Scan(&passwordHash)
			want, _ := sessionHash(a.Token)
			if hash != want || hash == a.Token || strings.Contains(passwordHash, adminPassword) {
				t.Fatal("plaintext credential persisted")
			}
			s.Close()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := me(t, s, a.Token); err != nil {
				t.Fatal("valid persisted session rejected", err)
			}
			now := time.Now().Unix()
			switch scenario {
			case "logout":
				if _, err := s.Manage(t.Context(), a.Token, "127.0.0.1", ManagementRequest{Operation: "logout"}); err != nil {
					t.Fatal(err)
				}
			case "idle":
				_, err = s.db.Exec("UPDATE admin_sessions SET last_used=?", now-1800)
			case "absolute":
				_, err = s.db.Exec("UPDATE admin_sessions SET expires_at=?", now)
			case "clock":
				_, err = s.db.Exec("UPDATE admin_clock SET high=?", now+60)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = me(t, s, a.Token)
			if scenario == "clock" {
				if !errors.Is(err, ErrAdminUnavailable) {
					t.Fatal("rollback accepted", err)
				}
			} else if !errors.Is(err, ErrAdminUnauthorized) {
				t.Fatal("expired/revoked session accepted", err)
			}
		})
	}
}
func TestLoginLimitsPersistAndDoNotEnumerateAccounts(t *testing.T) {
	s, dir := openTest(t)
	account(t, s, "operator", adminauth.Admin)
	for i := 0; i < 5; i++ {
		if _, err := s.Login(t.Context(), "nonexistent", adminPassword, "127.0.0.1"); !errors.Is(err, ErrAdminUnauthorized) {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Login(t.Context(), "nonexistent", adminPassword, "127.0.0.1"); !errors.Is(err, ErrAdminLimited) {
		t.Fatal("restart cleared login budget", err)
	}
	for _, name := range []string{"operator", "missing"} {
		if _, err := s.Login(t.Context(), name, "wrong", "127.0.0.2"); !errors.Is(err, ErrAdminUnauthorized) {
			t.Fatal("credential failure differs", err)
		}
	}
	var before, after int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&before)
	for i := 0; i < 20; i++ {
		_, _ = s.Login(t.Context(), "nonexistent", adminPassword, "127.0.0.1")
	}
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&after)
	if after-before > 2 {
		t.Fatal("rate-limited traffic floods audit", after-before)
	}
}

func TestSessionCapacityAndLocalGlobalRevocation(t *testing.T) {
	s, _ := openTest(t)
	account(t, s, "operator", adminauth.Admin)
	var tokens []string
	for i := 0; i < 8; i++ {
		if _, err := s.db.Exec("DELETE FROM admin_limits"); err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, login(t, s, "operator").Token)
	}
	if _, err := s.Login(t.Context(), "operator", adminPassword, "127.0.0.1"); !errors.Is(err, ErrAdminLimited) {
		t.Fatal("session count unbounded", err)
	}
	if err := s.RevokeAllSessions(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if err := me(t, s, token); !errors.Is(err, ErrAdminUnauthorized) {
			t.Fatal("global revocation missed a session", err)
		}
	}
	if _, err := s.Login(t.Context(), "operator", adminPassword, "127.0.0.1"); err != nil {
		t.Fatal("revocation removed account credentials", err)
	}
}
func TestLogoutAndAccountRevocationUseReservedAuditCapacity(t *testing.T) {
	for _, accountChange := range []bool{false, true} {
		s, _ := openTest(t)
		account(t, s, "operator", adminauth.Admin)
		a := login(t, s, "operator")
		var seq int64
		var reserved int
		s.db.QueryRow("SELECT sequence,reserved FROM audit_head").Scan(&seq, &reserved)
		target := audit.Capacity - reserved
		if _, err := s.db.Exec("UPDATE audit_events SET sequence=? WHERE sequence=?", target, seq); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec("UPDATE audit_head SET sequence=?", target); err != nil {
			t.Fatal(err)
		}
		if err := me(t, s, a.Token); !errors.Is(err, audit.ErrCapacity) {
			t.Fatal("audit capacity not enforced", err)
		}
		var err error
		if accountChange {
			err = s.ChangeUser(t.Context(), "operator", "disable", "")
		} else {
			_, err = s.Manage(t.Context(), a.Token, "127.0.0.1", ManagementRequest{Operation: "logout"})
		}
		if err != nil {
			t.Fatal("reserved revocation failed", err)
		}
		if err := me(t, s, a.Token); !errors.Is(err, ErrAdminUnauthorized) {
			t.Fatal("revoked session still valid", err)
		}
	}
}
