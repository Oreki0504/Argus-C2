package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/localdb"
)

// Explicit, additive migrations. Older binaries reject version 104; the Agent
// schema and protocol are unchanged. No server startup silently upgrades state.
const consoleSchema = `
ALTER TABLE audit_events ADD COLUMN subject_id TEXT NOT NULL DEFAULT '';
CREATE TABLE console_state (
 id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL DEFAULT 0,
 recovery INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0,
 bootstrap_digest TEXT NOT NULL DEFAULT '', bootstrap_expires INTEGER NOT NULL DEFAULT 0,
 bootstrap_attempts INTEGER NOT NULL DEFAULT 0, provider_id TEXT NOT NULL DEFAULT ''
);
INSERT INTO console_state(id) VALUES(1);
CREATE TABLE console_users (
 id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL, name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('Admin','User')),
 status TEXT NOT NULL CHECK(status IN ('pending','active','disabled')),
 version INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL,
 last_login_at INTEGER, UNIQUE(issuer,subject)
);
CREATE INDEX console_users_status ON console_users(status,id);
CREATE TABLE console_nodes (
 node_id TEXT PRIMARY KEY REFERENCES nodes(id), public_id TEXT NOT NULL UNIQUE,
 display_name TEXT NOT NULL DEFAULT ''
);
INSERT INTO console_nodes(node_id,public_id) SELECT id,lower(hex(randomblob(16))) FROM nodes;
CREATE TRIGGER console_node_registered AFTER INSERT ON nodes BEGIN
 INSERT INTO console_nodes(node_id,public_id) VALUES(NEW.id,lower(hex(randomblob(16))));
END;
CREATE INDEX console_tasks_type_created ON tasks(task_type,created_at DESC,id DESC);
CREATE INDEX console_results_node_received ON results(node_id,received_at DESC);
CREATE INDEX console_audit_subject ON audit_events(subject_id,id DESC);
PRAGMA user_version=103;
`

const consoleAccountSchema = `
CREATE TABLE console_identities (
 issuer TEXT NOT NULL, subject TEXT NOT NULL,
 user_id TEXT NOT NULL REFERENCES console_users(id) ON DELETE CASCADE,
 created_at INTEGER NOT NULL, PRIMARY KEY(issuer,subject)
);
INSERT INTO console_identities SELECT issuer,subject,id,created_at FROM console_users;
CREATE INDEX console_identities_user ON console_identities(user_id);
CREATE TABLE console_token (
 id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL,
 user_id TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL
);
PRAGMA user_version=104;
`

// MigrateConsole requires a stopped server and a new private backup destination.
// Backup is durable and verified before the transactional DDL begins. A failed
// migration leaves the original schema intact and its backup available.
func MigrateConsole(ctx context.Context, dir, backup string) error {
	lock, err := localdb.LockServer(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	parent, err := os.Lstat(filepath.Dir(backup))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return errors.New("backup directory must be private and non-symlink")
	}
	db, err := localdb.Open(dir, "argus.db", false)
	if err != nil {
		return err
	}
	defer db.Close()
	var version, component int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&component); err != nil {
		return err
	}
	if (version != 102 && version != 103) || component != applicationID {
		return errors.New("migration requires an ARGS schema 102 or 103 database")
	}
	originalVersion := version
	s := &Store{DB: db}
	if err = s.backupVersion(ctx, backup, version); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != originalVersion {
		return errors.New("database changed during migration")
	}
	migration := consoleAccountSchema
	if version == 102 {
		migration = consoleSchema + migration
	}
	if _, err = tx.ExecContext(ctx, migration); err != nil {
		return err
	}
	if err = auditSubject(ctx, tx, "local", "console.migrate", "", "", "", "104"); err != nil {
		return err
	}
	return tx.Commit()
}
