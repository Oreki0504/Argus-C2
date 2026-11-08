package database

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/localdb"
)

func TestConsole103MigrationPreservesLinkedOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "state")
	db, err := localdb.Open(dir, "argus.db", true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(schema + consoleSchema + `UPDATE console_state SET initialized=1,generation=3,provider_id='provider'; INSERT INTO console_users(id,name,issuer,subject,role,status,created_at) VALUES('owner','Existing owner','https://github.com','42','Admin','active',1);`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err = MigrateConsole(context.Background(), dir, filepath.Join(root, "backup.db")); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.FinishConsoleLogin(context.Background(), 3, "provider", "https://github.com", "42", "Existing owner", false)
	if err != nil || u.ID != "owner" || u.Role != "Admin" {
		t.Fatal("existing account changed", u, err)
	}
	items, err := s.ConsoleIdentities(context.Background(), u.ID)
	if err != nil || len(items) != 1 {
		t.Fatal("missing migrated identity", items, err)
	}
	if enabled, err := s.ConsoleTokenAvailable(context.Background()); err != nil || enabled {
		t.Fatal("upgrade added unauthorized token", err)
	}
}

func TestConsoleTokenAtomicActivationAndLongLivedLogin(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	secret, err := s.IssueConsoleToken(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	s.clock = func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }
	var group sync.WaitGroup
	ids := make(chan string, 5)
	for i := 0; i < 5; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			u, _, err := s.LoginConsoleToken(ctx, secret)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- u.ID
		}()
	}
	group.Wait()
	close(ids)
	id := ""
	for got := range ids {
		if id != "" && got != id {
			t.Fatal("multiple owners")
		}
		id = got
	}
	if id == "" {
		t.Fatal("no owner")
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM console_users").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	var digest string
	if err = s.DB.QueryRow("SELECT digest FROM console_token").Scan(&digest); err != nil || digest == secret || digest != TokenDigest(secret) {
		t.Fatal("token storage", err)
	}
}

func TestLegacyBootstrapCanEnterDirectlyOnlyWhileValid(t *testing.T) {
	for _, expired := range []bool{false, true} {
		s, err := Open(filepath.Join(t.TempDir(), "state"), true)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := s.IssueConsoleBootstrap(context.Background(), false)
		if err != nil {
			t.Fatal(err)
		}
		if expired {
			s.clock = func() time.Time { return time.Now().Add(time.Hour) }
		}
		u, _, err := s.LoginConsoleToken(context.Background(), secret)
		if expired && err == nil || !expired && (err != nil || u.Role != "Admin") {
			t.Fatal("legacy validity", err)
		}
		s.Close()
	}
}
