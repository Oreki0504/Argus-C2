package enrollment

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

type Service struct {
	Store  *database.Store
	Issuer *Issuer
}

func (s Service) Enroll(ctx context.Context, r protocol.EnrollmentRequest, metadata protocol.AgentMetadata) (protocol.EnrollmentResponse, error) {
	var out protocol.EnrollmentResponse
	if !metadata.Valid() || len(r.Token) < 40 || len(r.Token) > 256 || r.Hostname == "" || !protocol.CleanText(r.Hostname, 255) {
		return out, errors.New("invalid enrollment")
	}
	csr, e := ParseCSR(r.CSR)
	if e != nil {
		return out, e
	}
	keyID := database.TokenDigest(string(csr.RawSubjectPublicKeyInfo))
	e = s.Store.Write(ctx, func(tx *sql.Tx) error {
		var expires int64
		var id sql.NullString
		var oldKey string
		if e := tx.QueryRowContext(ctx, "SELECT expires_at,node_id,csr_fingerprint FROM enrollment_tokens WHERE digest=?", database.TokenDigest(r.Token)).Scan(&expires, &id, &oldKey); e != nil || expires <= time.Now().Unix() {
			return database.ErrUnauthorized
		}
		if id.Valid {
			if oldKey != keyID {
				return database.ErrUnauthorized
			}
			var status string
			out.NodeID = id.String
			if e := tx.QueryRowContext(ctx, "SELECT certificate,status FROM nodes WHERE id=?", id.String).Scan(&out.Certificate, &status); e != nil {
				return e
			}
			if status != "active" {
				return database.ErrUnauthorized
			}
			return nil
		}
		out.NodeID = identity.RandomID()
		var cert *x509.Certificate
		var e error
		out.Certificate, cert, e = s.Issuer.Issue(r.CSR, out.NodeID)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate,protocol_version,agent_version) VALUES(?,?,?,'active',?,?,?,?,?)", out.NodeID, r.Hostname, identity.Fingerprint(cert), time.Now().Unix(), cert.NotAfter.Unix(), out.Certificate, metadata.ProtocolVersion, metadata.AgentVersion); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE enrollment_tokens SET node_id=?,csr_fingerprint=? WHERE digest=?", out.NodeID, keyID, database.TokenDigest(r.Token)); e != nil {
			return e
		}
		return database.Audit(ctx, tx, out.NodeID, "node.enroll", out.NodeID, "", "succeeded")
	})
	return out, e
}
func (s Service) Renew(ctx context.Context, peer *x509.Certificate, csrBytes []byte) (protocol.EnrollmentResponse, error) {
	var out protocol.EnrollmentResponse
	csr, e := ParseCSR(csrBytes)
	if e != nil {
		return out, e
	}
	if peer == nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, peer.RawSubjectPublicKeyInfo) {
		return out, database.ErrInvalidRenewal
	}
	e = s.Store.Write(ctx, func(tx *sql.Tx) error {
		id, e := database.Authorize(ctx, tx, peer)
		if e != nil {
			return e
		}
		out.NodeID = id
		var fingerprint string
		if e = tx.QueryRowContext(ctx, "SELECT certificate,certificate_fingerprint FROM nodes WHERE id=?", id).Scan(&out.Certificate, &fingerprint); e != nil {
			return e
		}
		// A lost response can be retried using the previous leaf until its original expiry.
		if fingerprint != identity.Fingerprint(peer) {
			return nil
		}
		if time.Until(peer.NotAfter) > 7*24*time.Hour {
			return nil
		}
		var cert *x509.Certificate
		out.Certificate, cert, e = s.Issuer.Issue(csrBytes, id)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE nodes SET certificate=?,certificate_fingerprint=?,certificate_expires_at=?,previous_fingerprint=?,previous_until=? WHERE id=?", out.Certificate, identity.Fingerprint(cert), cert.NotAfter.Unix(), fingerprint, peer.NotAfter.Unix(), id); e != nil {
			return e
		}
		return database.Audit(ctx, tx, id, "node.renew", id, "", "succeeded")
	})
	return out, e
}
