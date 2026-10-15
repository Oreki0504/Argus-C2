package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func migrateSigners(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, "ALTER TABLE dispatch_settings ADD COLUMN trust_json BLOB; ALTER TABLE dispatch_settings ADD COLUMN paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0,1)); PRAGMA user_version=5;"); err != nil {
		return err
	}
	return audit.Append(ctx, tx, audit.Event{Kind: "signer_schema_migrated", ActorID: "local-operator", Source: "local", Status: "succeeded", Code: "server_schema_5"}, 0)
}

func dispatchSettings(ctx context.Context, tx *sql.Tx) (string, *signing.TrustSet, bool, error) {
	var id string
	var data []byte
	var paused bool
	if err := tx.QueryRowContext(ctx, "SELECT key_digest,trust_json,paused FROM dispatch_settings WHERE id=1").Scan(&id, &data, &paused); err != nil {
		return "", nil, false, err
	}
	if data == nil {
		return id, nil, paused, nil
	}
	s, err := signing.DecodeTrust(data)
	if err != nil {
		return "", nil, false, err
	}
	canonical, err := s.Canonical()
	if err != nil || !bytes.Equal(data, canonical) {
		return "", nil, false, errors.New("noncanonical stored signer trust")
	}
	if _, err := s.Key(id); err != nil {
		return "", nil, false, err
	}
	return id, &s, paused, nil
}

// PauseDispatch serializes against admission and signing. Result delivery and
// telemetry stay available, including results signed before the maintenance.
func (s *Store) PauseDispatch(ctx context.Context, paused bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	id, trust, old, err := dispatchSettings(ctx, tx)
	if err != nil {
		return err
	}
	if old == paused {
		return tx.Commit()
	}
	if !paused && trust != nil {
		k, err := trust.Key(id)
		if err != nil {
			return err
		}
		if now := time.Now().Unix(); now < k.NotBefore || now >= k.NotAfter {
			return errors.New("selected signer is outside its validity window")
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE dispatch_settings SET paused=? WHERE id=1", paused); err != nil {
		return err
	}
	status := "ready"
	if paused {
		status = "paused"
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "dispatch_state_changed", ActorID: "local-operator", Source: "local", Status: status}, 0); err != nil {
		return err
	}
	return tx.Commit()
}

// InstallSignerTrust changes only server-local trust while dispatch is paused.
// expected is the current canonical trust digest, or the initial raw-key digest.
// Live envelopes must still verify under the proposed trust; expired envelopes
// remain byte-for-byte in state and can still receive their reserved late result.
func (s *Store) InstallSignerTrust(ctx context.Context, expected string, next signing.TrustSet) error {
	data, err := next.Canonical()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	id, previous, paused, err := dispatchSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !paused {
		return errors.New("pause dispatch before installing signer trust")
	}
	if err := audit.Verify(ctx, tx); err != nil {
		return err
	}
	var health string
	if err := tx.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&health); err != nil || health != "ok" {
		return errors.New("server database integrity check failed")
	}
	oldDigest := id
	if previous != nil {
		old, err := previous.Canonical()
		if err != nil {
			return err
		}
		if bytes.Equal(old, data) {
			return tx.Commit()
		}
		oldDigest = audit.Digest(old)
	}
	if expected != oldDigest {
		return errors.New("current server signer trust changed")
	}
	if err := signing.CheckTransition(previous, id, next); err != nil {
		return err
	}
	if _, err := next.Key(id); err != nil {
		return errors.New("switch the selected signer before retiring it")
	}
	rows, err := tx.QueryContext(ctx, "SELECT payload,envelope FROM tasks WHERE state='dispatched' AND expires_at>? LIMIT ?", time.Now().Unix(), MaxStoredTasks+1)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		count++
		var payload, wire []byte
		if err := rows.Scan(&payload, &wire); err != nil {
			rows.Close()
			return err
		}
		_, signed, _, err := signing.VerifyTrusted(wire, next, time.Now())
		if count > MaxStoredTasks || err != nil || !bytes.Equal(payload, signed) {
			rows.Close()
			return errors.New("drain live envelopes or wait for their expiry before changing trust")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE dispatch_settings SET trust_json=? WHERE id=1", data); err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "signer_trust_changed", ActorID: "local-operator", Source: "local", Status: "succeeded", PayloadDigest: oldDigest, ResultDigest: audit.Digest(data)}, 0); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SwitchSigner(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	old, trust, paused, err := dispatchSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !paused || trust == nil {
		return errors.New("paused dispatch and installed signer trust are required")
	}
	k, err := trust.Key(id)
	if err != nil {
		return err
	}
	if now := time.Now().Unix(); now < k.NotBefore || now >= k.NotAfter {
		return errors.New("new signer is outside its validity window")
	}
	if old == id {
		return tx.Commit()
	}
	var queued int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM tasks WHERE state='queued'").Scan(&queued); err != nil {
		return err
	}
	if queued != 0 {
		return errors.New("drain or explicitly cancel queued tasks before switching signer")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE dispatch_settings SET key_digest=? WHERE id=1", id); err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "signer_selected", ActorID: "local-operator", Source: "local", Status: "succeeded", PayloadDigest: old, ResultDigest: id}, 0); err != nil {
		return err
	}
	return tx.Commit()
}

// CancelQueuedForSignerChange explicitly terminalizes undispatched work. It
// leaves every payload/request ID intact, and never touches dispatched work or
// its reserved result slot. The caller must pause dispatch first.
func (s *Store) CancelQueuedForSignerChange(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, _, paused, err := dispatchSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !paused {
		return errors.New("pause dispatch before cancelling queued work")
	}
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM tasks WHERE state='queued' ORDER BY sequence LIMIT ?", MaxStoredTasks+1)
	if err != nil {
		return err
	}
	var tasks [][]byte
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return err
		}
		tasks = append(tasks, payload)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(tasks) > MaxStoredTasks {
		return errors.New("invalid task capacity")
	}
	for _, payload := range tasks {
		t, err := protocol.DecodeTask(payload)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tasks SET state='rejected',code='signer_changed_before_dispatch' WHERE request_id=? AND state='queued'", t.RequestID); err != nil {
			return err
		}
		if err := audit.Append(ctx, tx, audit.TaskEvent("task_cancelled", t, "local", "rejected", "signer_changed_before_dispatch", audit.Digest(payload)), -2); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type SignerStatus struct {
	KeyID  string            `json:"selected_key_id"`
	Paused bool              `json:"dispatch_paused"`
	Trust  *signing.TrustSet `json:"trust_set"`
}

func (s *Store) Signers(ctx context.Context) (SignerStatus, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SignerStatus{}, err
	}
	defer tx.Rollback()
	id, trust, paused, err := dispatchSettings(ctx, tx)
	if err != nil {
		return SignerStatus{}, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "signers_read", ActorID: "local-operator", Source: "local", Status: "succeeded"}, 0); err != nil {
		return SignerStatus{}, err
	}
	return SignerStatus{id, paused, trust}, tx.Commit()
}
