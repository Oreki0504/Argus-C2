package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/localdb"
)

func TestConsoleMigrationBackupRollbackAndLock(t *testing.T) {
	for _, mode := range []string{"success", "ddl_failure", "locked"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "state")
			db, err := localdb.Open(dir, "argus.db", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(schema); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('old-node','private-host','fp','active',1,9999999999,'old-cert'); INSERT INTO audit_events(timestamp,actor,action,node_id,task_id,status) VALUES(1,'admin','old.audit','','','ok')`); err != nil {
				t.Fatal(err)
			}
			if mode == "ddl_failure" {
				if _, err = db.Exec("CREATE TABLE console_state(preserved TEXT)"); err != nil {
					t.Fatal(err)
				}
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			if s, err := Open(dir, false); err == nil {
				s.Close()
				t.Fatal("startup silently accepted 102")
			}
			if mode == "locked" {
				lock, err := localdb.LockServer(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			}
			backup := filepath.Join(root, "before.db")
			err = MigrateConsole(ctx, dir, backup)
			if mode == "success" && err != nil {
				t.Fatal(err)
			}
			if mode != "success" && err == nil {
				t.Fatal("migration should fail")
			}
			db, err = localdb.Open(dir, "argus.db", false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			var host, action string
			if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
				t.Fatal(err)
			}
			want := 102
			if mode == "success" {
				want = SchemaVersion
			}
			if version != want {
				t.Fatalf("version %d != %d", version, want)
			}
			if err = db.QueryRow("SELECT hostname FROM nodes WHERE id='old-node'").Scan(&host); err != nil || host != "private-host" {
				t.Fatal(host, err)
			}
			if err = db.QueryRow("SELECT action FROM audit_events WHERE id=1").Scan(&action); err != nil || action != "old.audit" {
				t.Fatal(action, err)
			}
			if mode == "success" {
				var count int
				if err = db.QueryRow("SELECT count(*) FROM console_nodes WHERE node_id='old-node'").Scan(&count); err != nil || count != 1 {
					t.Fatal(count, err)
				}
			}
			if mode == "ddl_failure" {
				var count int
				if err = db.QueryRow("SELECT count(*) FROM pragma_table_info('audit_events') WHERE name='subject_id'").Scan(&count); err != nil || count != 0 {
					t.Fatal("partial DDL committed", count, err)
				}
			}
			if mode != "locked" {
				snapshot, err := sql.Open("sqlite", "file:"+backup+"?mode=ro")
				if err != nil {
					t.Fatal(err)
				}
				defer snapshot.Close()
				var original int
				if err = snapshot.QueryRow("PRAGMA user_version").Scan(&original); err != nil || original != 102 {
					t.Fatal("backup is not original schema", original, err)
				}
			}
		})
	}
}
func TestConsoleBootstrapAtomicBindingAndRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	secret, err := s.IssueConsoleBootstrap(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := s.ProveConsoleBootstrap(ctx, secret); err == nil {
				success.Add(1)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("bootstrap consumed more than once", success.Load())
	}
	state, err := s.ConsoleState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetConsoleProvider(ctx, state.Generation, "provider-one"); err != nil {
		t.Fatal(err)
	}
	success.Store(0)
	for range 12 {
		wg.Go(func() {
			if _, err := s.FinishConsoleLogin(ctx, state.Generation, "provider-one", "https://identity.example", "owner", "Owner", true); err == nil {
				success.Add(1)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("multiple first owners", success.Load())
	}
	owner, err := s.FinishConsoleLogin(ctx, state.Generation, "provider-one", "https://identity.example", "owner", "Owner", false)
	if err != nil || owner.Role != "Admin" {
		t.Fatal(owner, err)
	}
	if _, err = s.IssueConsoleBootstrap(ctx, false); !errors.Is(err, ErrSetupClosed) {
		t.Fatal("active bootstrap reopened", err)
	}
	if _, err = s.UpdateConsoleUser(ctx, "someone-else", owner.ID, "User", "active", owner.Subject, owner.Version); !errors.Is(err, ErrLastAdmin) {
		t.Fatal("last admin removed", err)
	}
	oldCtx := WithConsoleActor(ctx, owner.ID, owner.Version, state.Generation, true)
	recovery, err := s.IssueConsoleBootstrap(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateToken(oldCtx, "web:"+owner.ID, time.Minute); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("recovery did not revoke old write", err)
	}
	state, err = s.ProveConsoleBootstrap(ctx, recovery)
	if err != nil {
		t.Fatal(err)
	}
	newOwner, err := s.FinishConsoleLogin(ctx, state.Generation, "provider-one", "https://identity.example", "new-owner", "New owner", true)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.ConsoleUser(ctx, owner.ID)
	if err != nil || old.Status != "disabled" || newOwner.Role != "Admin" {
		t.Fatal(old, newOwner, err)
	}
}
func TestConsoleBootstrapLimitsAndTransactionalRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	secret, err := s.IssueConsoleBootstrap(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err = s.ProveConsoleBootstrap(ctx, "invalid"); !errors.Is(err, ErrBootstrapInvalid) {
			t.Fatal(err)
		}
	}
	if _, err = s.ProveConsoleBootstrap(ctx, secret); !errors.Is(err, ErrBootstrapInvalid) {
		t.Fatal("attempt budget bypass", err)
	}
	secret, err = s.IssueConsoleBootstrap(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s.clock = func() time.Time { return start.Add(16 * time.Minute) }
	if _, err = s.ProveConsoleBootstrap(ctx, secret); !errors.Is(err, ErrBootstrapInvalid) {
		t.Fatal("expired proof accepted", err)
	}
	s.clock = nil
	secret, err = s.IssueConsoleBootstrap(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.ProveConsoleBootstrap(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetConsoleProvider(ctx, state.Generation, "p"); err != nil {
		t.Fatal(err)
	}
	u, err := s.FinishConsoleLogin(ctx, state.Generation, "p", "https://id.example", "owner", "Owner", true)
	if err != nil {
		t.Fatal(err)
	}
	current := WithConsoleActor(ctx, u.ID, u.Version, state.Generation, true)
	if err = s.RevokeConsoleSessions(current, u.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateToken(current, u.ID, time.Minute); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("stale authorization wrote", err)
	}
	second, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	persisted, err := second.ConsoleState(ctx)
	if err != nil || !persisted.Initialized || persisted.BootstrapDigest != "" {
		t.Fatal(persisted, err)
	}
}
