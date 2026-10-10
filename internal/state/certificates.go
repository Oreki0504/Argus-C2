package state

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

var ErrRenewal = errors.New("certificate renewal rejected")

// Legacy registrations retain their exact leaf pin. Unknown legacy metadata is
// explicitly zero/empty, never fabricated; authenticated renewal fills it in.
func migrateCertificates(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `CREATE TABLE node_credentials (
 certificate_sha256 TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES nodes(agent_id),
 epoch TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 64),
 issuer_sha256 TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '', public_key_sha256 TEXT NOT NULL DEFAULT '',
 not_before INTEGER NOT NULL DEFAULT 0, not_after INTEGER NOT NULL DEFAULT 0,
 retire_at INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 issued_at INTEGER NOT NULL, UNIQUE(agent_id,generation)
);
CREATE UNIQUE INDEX credential_issuer_serial ON node_credentials(issuer_sha256,serial) WHERE issuer_sha256<>'';
INSERT INTO node_credentials(certificate_sha256,agent_id,epoch,generation,issued_at)
 SELECT certificate_sha256,agent_id,enrollment_epoch,1,enrolled_at FROM nodes;
CREATE TABLE certificate_renewals (
 agent_id TEXT NOT NULL REFERENCES nodes(agent_id), renewal_id TEXT NOT NULL,
 authorizing_sha256 TEXT NOT NULL REFERENCES node_credentials(certificate_sha256), csr_sha256 TEXT NOT NULL,
 certificate_sha256 TEXT NOT NULL REFERENCES node_credentials(certificate_sha256), response BLOB NOT NULL,
 PRIMARY KEY(agent_id,renewal_id)
);
PRAGMA user_version=4;`)
	if err != nil {
		return err
	}
	return audit.Append(ctx, tx, audit.Event{Kind: "credentials_migrated", ActorID: "local-operator", Source: "local", Status: "succeeded", Code: "server_schema_4"}, 0)
}

type certificateQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func authorizeCertificate(ctx context.Context, q certificateQuery, cert *x509.Certificate) (identity.Node, error) {
	n, err := identity.FromCertificate(cert)
	if err != nil {
		return n, err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return n, errors.New("certificate outside validity window")
	}
	var exists int
	err = q.QueryRowContext(ctx, `SELECT 1 FROM nodes n JOIN node_credentials c ON c.agent_id=n.agent_id
 WHERE n.agent_id=? AND n.enrollment_epoch=? AND n.enabled=1 AND c.epoch=n.enrollment_epoch
 AND c.certificate_sha256=? AND c.revoked=0 AND (c.retire_at=0 OR c.retire_at>?)
 AND (c.not_after=0 OR (c.not_before<=? AND c.not_after>?))`, n.AgentID, n.EnrollmentEpoch, identity.Fingerprint(cert), now.Unix(), now.Unix(), now.Unix()).Scan(&exists)
	if err != nil {
		return n, errors.New("node credential is not authorized")
	}
	return n, nil
}

func credentialMetadata(ctx context.Context, tx *sql.Tx, cert, issuer *x509.Certificate) error {
	if cert == nil || issuer == nil || cert.CheckSignatureFrom(issuer) != nil {
		return errors.New("invalid credential issuer")
	}
	_, err := tx.ExecContext(ctx, `UPDATE node_credentials SET issuer_sha256=?,serial=?,public_key_sha256=?,not_before=?,not_after=? WHERE certificate_sha256=?`, identity.Fingerprint(issuer), cert.SerialNumber.String(), audit.Digest(cert.RawSubjectPublicKeyInfo), cert.NotBefore.Unix(), cert.NotAfter.Unix(), identity.Fingerprint(cert))
	return err
}

// Issuance is a local, bounded cryptographic operation, never network I/O. The
// immediate transaction serializes it with disablement and concurrent renewals.
type CertificateIssuer interface {
	Issue(*x509.CertificateRequest, identity.Node) ([]byte, *x509.Certificate, error)
	Certificate() *x509.Certificate
}

func (s *Store) RenewCertificate(ctx context.Context, old, oldIssuer *x509.Certificate, id string, csr *x509.CertificateRequest, issuer CertificateIssuer, source string) ([]byte, error) {
	if !identity.Hex(id, 32) || csr == nil || len(csr.Raw) == 0 || len(csr.Raw) > 2048 || issuer == nil {
		return nil, ErrRenewal
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	n, err := authorizeCertificate(ctx, tx, old)
	if err != nil {
		return nil, err
	}
	oldHash, csrHash := identity.Fingerprint(old), audit.Digest(csr.Raw)
	var auth, digest, nextHash string
	var saved []byte
	err = tx.QueryRowContext(ctx, "SELECT authorizing_sha256,csr_sha256,certificate_sha256,response FROM certificate_renewals WHERE agent_id=? AND renewal_id=?", n.AgentID, id).Scan(&auth, &digest, &nextHash, &saved)
	if err == nil {
		if auth != oldHash || digest != csrHash {
			return nil, ErrRenewal
		}
		r, err := protocol.DecodeRenewalResponse(saved)
		if err != nil || r.AgentID != n.AgentID || r.Epoch != n.EnrollmentEpoch || r.RenewalID != id || r.PreviousSHA256 != oldHash {
			return nil, ErrRenewal
		}
		block, _ := pem.Decode([]byte(r.CertificatePEM))
		if block == nil {
			return nil, ErrRenewal
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || identity.Fingerprint(cert) != nextHash {
			return nil, ErrRenewal
		}
		if _, err := authorizeCertificate(ctx, tx, cert); err != nil {
			return nil, ErrRenewal
		}
		// No new issuance or audit append on a byte-identical retrieval.
		return saved, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var generation, latest, active, used int
	var issued int64
	if err := tx.QueryRowContext(ctx, "SELECT generation,issued_at FROM node_credentials WHERE certificate_sha256=?", oldHash).Scan(&generation, &issued); err != nil {
		return nil, err
	}
	now := time.Now()
	if err := tx.QueryRowContext(ctx, `SELECT MAX(generation),COUNT(*),COALESCE(SUM(CASE WHEN revoked=0 AND (retire_at=0 OR retire_at>?) AND (not_after=0 OR not_after>?) THEN 1 ELSE 0 END),0) FROM node_credentials WHERE agent_id=?`, now.Unix(), now.Unix(), n.AgentID).Scan(&latest, &used, &active); err != nil {
		return nil, err
	}
	if generation != latest || active >= 2 || used >= protocol.MaxCertificateGenerations || (generation > 1 && now.Unix()-issued < 3600) {
		return nil, ErrRenewal
	}
	if err := credentialMetadata(ctx, tx, old, oldIssuer); err != nil {
		return nil, err
	}
	chain, cert, err := issuer.Issue(csr, n)
	if err != nil {
		return nil, err
	}
	actual, err := identity.FromCertificate(cert)
	if err != nil || actual != n || !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) || cert.NotAfter.After(now.Add(30*24*time.Hour+time.Minute)) || !cert.NotAfter.After(now.Add(time.Minute)) {
		return nil, ErrRenewal
	}
	nextHash = identity.Fingerprint(cert)
	cutoff := now.Add(24 * time.Hour).Unix()
	if old.NotAfter.Unix() < cutoff {
		cutoff = old.NotAfter.Unix()
	}
	if cert.NotAfter.Unix() < cutoff {
		cutoff = cert.NotAfter.Unix()
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO node_credentials(certificate_sha256,agent_id,epoch,generation,issued_at) VALUES(?,?,?,?,?)", nextHash, n.AgentID, n.EnrollmentEpoch, latest+1, now.Unix()); err != nil {
		return nil, err
	}
	if err := credentialMetadata(ctx, tx, cert, issuer.Certificate()); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE node_credentials SET retire_at=? WHERE certificate_sha256=?", cutoff, oldHash); err != nil {
		return nil, err
	}
	r := protocol.RenewalResponse{Version: 1, RenewalID: id, AgentID: n.AgentID, Epoch: n.EnrollmentEpoch, Generation: latest + 1, PreviousSHA256: oldHash, PreviousValidUntil: cutoff, CertificatePEM: string(chain)}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if _, err := protocol.DecodeRenewalResponse(data); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO certificate_renewals VALUES(?,?,?,?,?,?)", n.AgentID, id, oldHash, csrHash, nextHash, data); err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "certificate_renewed", AgentID: n.AgentID, Epoch: n.EnrollmentEpoch, Source: source, Status: "succeeded", Code: "generation_" + strconv.Itoa(latest+1), PayloadDigest: csrHash, ResultDigest: nextHash}, 0); err != nil {
		return nil, err
	}
	// Also fail if the old credential expires while issuance is in progress.
	if _, err := authorizeCertificate(ctx, tx, old); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return data, nil
}

type Credential struct {
	SHA256          string `json:"certificate_sha256"`
	Generation      int    `json:"generation"`
	IssuerSHA256    string `json:"issuer_sha256"`
	Serial          string `json:"serial"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	NotBefore       int64  `json:"not_before"`
	NotAfter        int64  `json:"not_after"`
	RetireAt        int64  `json:"retire_at"`
	Revoked         bool   `json:"revoked"`
}

// Certificate maintenance is local administration; no remote account/CA or
// probe trust-management interface is introduced.
func (s *Store) Credentials(ctx context.Context, node string) ([]Credential, error) {
	if !identity.Hex(node, 32) {
		return nil, errors.New("invalid node ID")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT certificate_sha256,generation,issuer_sha256,serial,public_key_sha256,not_before,not_after,retire_at,revoked FROM node_credentials WHERE agent_id=? ORDER BY generation LIMIT 64", node)
	if err != nil {
		return nil, err
	}
	result := []Credential{}
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.SHA256, &c.Generation, &c.IssuerSHA256, &c.Serial, &c.PublicKeySHA256, &c.NotBefore, &c.NotAfter, &c.RetireAt, &c.Revoked); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "certificates_read", AgentID: node, ActorID: "local-operator", Source: "local", Status: "succeeded"}, 0); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

func (s *Store) RevokeCertificate(ctx context.Context, node, hash string) error {
	if !identity.Hex(node, 32) || !identity.Hex(hash, 64) {
		return errors.New("invalid credential selector")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE node_credentials SET revoked=1 WHERE agent_id=? AND certificate_sha256=?", node, hash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("credential not found")
	}
	if err := audit.Append(ctx, tx, audit.Event{Kind: "certificate_revoked", AgentID: node, ActorID: "local-operator", Source: "local", Status: "succeeded", PayloadDigest: hash}, 0); err != nil {
		return err
	}
	return tx.Commit()
}
