package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func createTrust(ctx context.Context, tx *sql.Tx, data []byte) error {
	_, err := tx.ExecContext(ctx, "CREATE TABLE probe_trust(id INTEGER PRIMARY KEY CHECK(id=1),document BLOB NOT NULL); INSERT INTO probe_trust VALUES(1,?); PRAGMA user_version=2;", data)
	return err
}

func checkTrustBinding(ctx context.Context, tx *sql.Tx, version int, digest string, key ed25519.PublicKey, trust *signing.TrustSet) error {
	if version == 1 && trust == nil && len(key) == ed25519.PublicKeySize && digest == audit.Digest(key) {
		return nil
	}
	if version != 2 || trust == nil {
		return errors.New("explicit local signer trust migration required")
	}
	want, err := trust.Canonical()
	if err != nil {
		return err
	}
	var stored []byte
	if err := tx.QueryRowContext(ctx, "SELECT document FROM probe_trust WHERE id=1").Scan(&stored); err != nil {
		return err
	}
	if !bytes.Equal(stored, want) {
		return errors.New("installed signer trust does not match replay binding")
	}
	return nil
}

// MigrateTrust holds the worker's exclusive process lock. It never initializes
// replay, recovers a running task, alters the clock, or installs a config file.
// The operator must keep the service stopped until the matching file is placed.
func MigrateTrust(ctx context.Context, dir string, node identity.Node, legacy ed25519.PublicKey, previous *signing.TrustSet, next signing.TrustSet) error {
	if node.Validate() != nil {
		return errors.New("invalid node identity")
	}
	if previous == nil && len(legacy) != ed25519.PublicKeySize {
		return errors.New("current pinned key required")
	}
	if err := signing.CheckTransition(previous, signing.KeyID(legacy), next); err != nil {
		return err
	}
	data, err := next.Canonical()
	if err != nil {
		return err
	}
	lock, err := localdb.Lock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	db, err := localdb.Open(dir, "probe.db", false)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	var health, id, epoch, digest string
	var high int64
	var blocked bool
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || (version != 1 && version != 2) {
		return errors.New("unknown probe schema")
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&health); err != nil || health != "ok" {
		return errors.New("probe integrity check failed")
	}
	if err := tx.QueryRowContext(ctx, "SELECT agent_id,epoch,key_digest,clock_high,clock_blocked FROM probe_meta WHERE id=1").Scan(&id, &epoch, &digest, &high, &blocked); err != nil {
		return err
	}
	if id != node.AgentID || epoch != node.EnrollmentEpoch {
		return errors.New("wrong replay identity")
	}
	if high <= 0 || blocked || time.Now().Unix() < high-protocol.MaxClockSkew {
		return ErrClock
	}
	if err := audit.Verify(ctx, tx); err != nil {
		return err
	}
	if err := verifyMigrationRecords(ctx, tx, node); err != nil {
		return err
	}
	if version == 2 {
		var stored []byte
		if err := tx.QueryRowContext(ctx, "SELECT document FROM probe_trust WHERE id=1").Scan(&stored); err != nil {
			return err
		}
		if bytes.Equal(stored, data) {
			return tx.Commit()
		} // Lost local success; no second audit event.
	}
	if err := checkTrustBinding(ctx, tx, version, digest, legacy, previous); err != nil {
		return err
	}
	oldDigest := digest
	if previous != nil {
		old, err := previous.Canonical()
		if err != nil {
			return err
		}
		oldDigest = audit.Digest(old)
	}
	if version == 1 {
		if err := createTrust(ctx, tx, data); err != nil {
			return err
		}
	} else if _, err := tx.ExecContext(ctx, "UPDATE probe_trust SET document=? WHERE id=1", data); err != nil {
		return err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "signer_trust_changed", AgentID: node.AgentID, Epoch: node.EnrollmentEpoch, Source: "local", ActorID: "local-operator", Status: "succeeded", PayloadDigest: oldDigest, ResultDigest: audit.Digest(data)}, 0); err != nil {
		return err
	}
	return tx.Commit()
}

func verifyMigrationRecords(ctx context.Context, tx *sql.Tx, node identity.Node) error {
	var reserved int
	if err := tx.QueryRowContext(ctx, "SELECT reserved FROM audit_head WHERE id=1").Scan(&reserved); err != nil {
		return err
	}
	if reserved != 0 {
		return errors.New("recover interrupted execution with the current trust before migration")
	}
	rows, err := tx.QueryContext(ctx, "SELECT epoch,request_id,payload,payload_digest,policy_digest,state,result,result_digest,delivered FROM executions LIMIT ?", MaxRecords+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var epoch, request, hash, policy, state, resultHash string
		var payload, result []byte
		var delivered bool
		if err := rows.Scan(&epoch, &request, &payload, &hash, &policy, &state, &result, &resultHash, &delivered); err != nil {
			return err
		}
		t, err := protocol.DecodeTask(payload)
		if err != nil || count > MaxRecords || t.AgentID != node.AgentID || epoch != node.EnrollmentEpoch || t.EnrollmentEpoch != epoch || t.RequestID != request || audit.Digest(payload) != hash || !identity.Hex(policy, 64) {
			return errors.New("corrupt replay assignment")
		}
		r, err := protocol.DecodeResult(result)
		if err != nil || r.CheckAssignment(t) != nil || string(r.Status) != state || r.PolicyDigest != policy || audit.Digest(result) != resultHash {
			return errors.New("corrupt or unfinished replay result")
		}
	}
	return rows.Err()
}
