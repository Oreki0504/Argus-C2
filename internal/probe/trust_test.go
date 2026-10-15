package probe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func probeTrust(t *testing.T, f *fixture) (signing.TrustSet, ed25519.PrivateKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	s, err := signing.Stage(f.key.Public().(ed25519.PublicKey), nil, pub, now, now.Add(time.Hour).Unix(), now.Add(48*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	return s, key
}

func closeProbe(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s = nil
}

func TestTrustMigrationPreservesReplayOutboxClockAndAudit(t *testing.T) {
	f := setup(t)
	trust, key := probeTrust(t, f)
	task := f.task()
	wire := f.envelope(task)
	first, err := f.e.Process(t.Context(), wire)
	if err != nil {
		t.Fatal(err)
	}
	pub := f.key.Public().(ed25519.PublicKey)
	if err := MigrateTrust(t.Context(), f.dir, f.node, pub, nil, trust); err == nil {
		t.Fatal("migrated a live worker")
	}
	var high, seq int64
	var hash string
	f.s.db.QueryRow("SELECT clock_high FROM probe_meta").Scan(&high)
	f.s.db.QueryRow("SELECT sequence,hash FROM audit_head").Scan(&seq, &hash)
	closeProbe(t, f)
	if s, err := OpenWithTrust(f.dir, f.node, trust); err == nil {
		s.Close()
		t.Fatal("file replacement silently migrated state")
	}
	if err := MigrateTrust(t.Context(), f.dir, f.node, pub, nil, trust); err != nil {
		t.Fatal(err)
	}
	if err := MigrateTrust(t.Context(), f.dir, f.node, pub, nil, trust); err != nil {
		t.Fatal("idempotent local retry", err)
	}
	if s, err := Open(f.dir, f.node, pub); err == nil {
		s.Close()
		t.Fatal("legacy downgrade")
	}
	f.s, err = OpenWithTrust(f.dir, f.node, trust)
	if err != nil {
		t.Fatal(err)
	}
	var preserved string
	var after int64
	var changes int
	f.s.db.QueryRow("SELECT hash FROM audit_events WHERE sequence=?", seq).Scan(&preserved)
	f.s.db.QueryRow("SELECT clock_high FROM probe_meta").Scan(&after)
	f.s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE kind='signer_trust_changed'").Scan(&changes)
	if preserved != hash || after < high || changes != 1 {
		t.Fatal("migration reset state or duplicated audit")
	}
	pending, err := f.s.Pending(t.Context())
	if err != nil || !bytes.Equal(first, pending) {
		t.Fatal("lost outbox", err)
	}
	f.e = NewEngine(f.s, f.path, "local")
	cached, err := f.e.Process(t.Context(), wire)
	if err != nil || !bytes.Equal(first, cached) {
		t.Fatal("lost legacy deduplication", err)
	}
	payload, _ := json.Marshal(task)
	// Re-signing identical payload bytes cannot reset the replay identity.
	newWire, err := signing.SignTrusted(payload, key, trust, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cached, err = f.e.Process(t.Context(), newWire)
	if err != nil || !bytes.Equal(first, cached) {
		t.Fatal("cross-key replay", err)
	}
	retired, err := signing.Retire(trust, signing.KeyID(pub))
	if err != nil {
		t.Fatal(err)
	}
	closeProbe(t, f)
	if err := MigrateTrust(t.Context(), f.dir, f.node, nil, &trust, retired); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenWithTrust(f.dir, f.node, trust); err == nil {
		s.Close()
		t.Fatal("accepted old trust file")
	}
	f.s, err = OpenWithTrust(f.dir, f.node, retired)
	if err != nil {
		t.Fatal(err)
	}
	f.e = NewEngine(f.s, f.path, "local")
	if _, err := f.e.Process(t.Context(), wire); err == nil {
		t.Fatal("accepted retired key, even for cached work")
	}
	pending, err = f.s.Pending(t.Context())
	if err != nil || !bytes.Equal(first, pending) {
		t.Fatal("retirement blocked outbox", err)
	}
	if err := f.s.Acknowledge(t.Context(), task.RequestID, audit.Digest(first)); err != nil {
		t.Fatal(err)
	}
	var accepted int
	f.s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE kind='task_accepted' AND request_id=?", task.RequestID).Scan(&accepted)
	if accepted != 1 {
		t.Fatal("task admitted more than once")
	}
}

func TestTrustMigrationFailsWithoutChangingOldBinding(t *testing.T) {
	for _, failure := range []string{"audit", "clock", "result", "schema", "identity", "current key"} {
		t.Run(failure, func(t *testing.T) {
			f := setup(t)
			trust, _ := probeTrust(t, f)
			pub := f.key.Public().(ed25519.PublicKey)
			node := f.node
			if failure == "result" {
				if _, err := f.e.Process(t.Context(), f.envelope(f.task())); err != nil {
					t.Fatal(err)
				}
			}
			switch failure {
			case "audit":
				f.s.db.Exec("CREATE TRIGGER fail_trust BEFORE INSERT ON audit_events WHEN NEW.kind='signer_trust_changed' BEGIN SELECT RAISE(ABORT,'disk full'); END")
			case "clock":
				f.s.db.Exec("UPDATE probe_meta SET clock_blocked=1")
			case "result":
				f.s.db.Exec("UPDATE executions SET result_digest='broken'")
			case "schema":
				f.s.db.Exec("PRAGMA user_version=99")
			case "identity":
				node = identity.New()
			case "current key":
				pub, _, _ = ed25519.GenerateKey(rand.Reader)
			}
			closeProbe(t, f)
			if err := MigrateTrust(t.Context(), f.dir, node, pub, nil, trust); err == nil {
				t.Fatal("migration accepted invalid state")
			}
			db, err := localdb.Open(f.dir, "probe.db", false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version int
			db.QueryRow("PRAGMA user_version").Scan(&version)
			if (failure != "schema" && version != 1) || (failure == "schema" && version != 99) {
				t.Fatal("migration partially committed", version)
			}
			var count int
			db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='probe_trust'").Scan(&count)
			if count != 0 {
				t.Fatal("trust table survived failed transaction")
			}
		})
	}
}

func TestMigrationRequiresInterruptedTaskRecovery(t *testing.T) {
	f := setup(t)
	trust, _ := probeTrust(t, f)
	task := f.task()
	payload, _ := json.Marshal(task)
	d, err := f.s.prepare(t.Context(), task, payload, f.p, "local", time.Now())
	if err != nil || !d.run {
		t.Fatal(err)
	}
	closeProbe(t, f)
	pub := f.key.Public().(ed25519.PublicKey)
	if err := MigrateTrust(t.Context(), f.dir, f.node, pub, nil, trust); err == nil {
		t.Fatal("migration discarded interrupted execution")
	}
	f.open(t)
	pending, err := f.s.Pending(t.Context())
	if err != nil || len(pending) == 0 {
		t.Fatal("missing recovered result", err)
	}
	closeProbe(t, f)
	if err := MigrateTrust(t.Context(), f.dir, f.node, pub, nil, trust); err != nil {
		t.Fatal(err)
	}
	f.s, err = OpenWithTrust(f.dir, f.node, trust)
	if err != nil {
		t.Fatal(err)
	}
	after, err := f.s.Pending(t.Context())
	if err != nil || !bytes.Equal(pending, after) {
		t.Fatal("lost indeterminate result", err)
	}
	if _, err := f.s.prepare(t.Context(), task, payload, f.p, "local", time.Now(), "unknown"); err == nil || errors.Is(err, ErrBusy) {
		t.Fatal("missing admission-time trust check")
	}
}
