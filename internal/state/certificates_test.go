package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

type countedIssuer struct {
	bundle *devpki.EnrollmentBundle
	calls  atomic.Int32
}

func testIssuer(t *testing.T) *countedIssuer {
	t.Helper()
	b, err := devpki.NewEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	return &countedIssuer{bundle: b}
}
func (i *countedIssuer) Certificate() *x509.Certificate { return i.bundle.Issuer.Leaf }
func (i *countedIssuer) Issue(csr *x509.CertificateRequest, n identity.Node) ([]byte, *x509.Certificate, error) {
	i.calls.Add(1)
	template, err := devpki.ClientTemplate(n)
	if err != nil {
		return nil, nil, err
	}
	template.NotAfter = time.Now().Add(12 * time.Hour)
	template.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template.SerialNumber.Add(template.SerialNumber, big.NewInt(1))
	der, err := x509.CreateCertificate(rand.Reader, &template, i.Certificate(), csr.PublicKey, i.bundle.Issuer.TLS.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), i.bundle.Issuer.PEM...)
	return chain, cert, err
}
func renewalCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}
func renewedLeaf(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	r, err := protocol.DecodeRenewalResponse(data)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(r.CertificatePEM))
	if block == nil {
		t.Fatal("missing leaf")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRenewalConcurrentRetryAndRestart(t *testing.T) {
	s, dir, b, key := taskStore(t)
	task := enqueue(t, s, b.Node.AgentID)
	envelope, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	issuer, csr, id := testIssuer(t), renewalCSR(t), identity.RandomID()
	outputs := make(chan []byte, 8)
	var wg sync.WaitGroup
	for j := 0; j < 8; j++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			db := s
			if j%2 == 0 {
				db = other
			}
			data, err := db.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, csr, issuer, "test")
			if err != nil {
				t.Error(err)
				return
			}
			outputs <- data
		}(j)
	}
	wg.Wait()
	close(outputs)
	var first []byte
	for data := range outputs {
		if first == nil {
			first = data
		}
		if !bytes.Equal(first, data) {
			t.Fatal("retry changed certificate")
		}
	}
	if issuer.calls.Load() != 1 || len(first) == 0 {
		t.Fatal("duplicate issuance", issuer.calls.Load())
	}
	if _, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, renewalCSR(t), issuer, "test"); err == nil {
		t.Fatal("renewal ID rebound to another CSR")
	}
	if _, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, identity.RandomID(), csr, issuer, "test"); err == nil {
		t.Fatal("older generation minted a third credential")
	}
	leaf := renewedLeaf(t, first)
	if _, err := s.RenewCertificate(t.Context(), leaf, issuer.Certificate(), identity.RandomID(), csr, issuer, "test"); err == nil {
		t.Fatal("overlap/generation rate limit ignored")
	}
	if err := other.Close(); err != nil {
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
	retry, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, csr, issuer, "test")
	if err != nil || !bytes.Equal(first, retry) {
		t.Fatal("lost committed issuance after restart", err)
	}
	again, err := s.Poll(t.Context(), leaf, task.PolicyDigest, key, "test")
	if err != nil || !bytes.Equal(envelope, again) {
		t.Fatal("renewal changed task assignment", err)
	}
	if _, err := s.SubmitResult(t.Context(), leaf, success(task), "test"); err != nil {
		t.Fatal("new credential cannot deliver old pending result", err)
	}
	if err := s.RevokeCertificate(t.Context(), b.Node.AgentID, identity.Fingerprint(b.Probe.Leaf)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(b.Probe.Leaf); err == nil {
		t.Fatal("revoked certificate still authorized")
	}
	if _, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, csr, issuer, "test"); err == nil {
		t.Fatal("retry bypassed revocation")
	}
	if _, err := s.Authorize(leaf); err != nil {
		t.Fatal("retiring old credential revoked new credential", err)
	}
	if err := s.Disable(t.Context(), b.Node.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(leaf); err == nil {
		t.Fatal("node disablement missed new generation")
	}
}

func TestRenewalAndRevocationAuditRollback(t *testing.T) {
	s, _, b, _ := taskStore(t)
	i, csr, id := testIssuer(t), renewalCSR(t), identity.RandomID()
	if _, err := s.db.Exec("CREATE TRIGGER deny_renewal BEFORE INSERT ON audit_events WHEN NEW.kind='certificate_renewed' BEGIN SELECT RAISE(ABORT,'full disk'); END"); err != nil {
		t.Fatal(err)
	}
	if data, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, csr, i, "test"); err == nil || len(data) != 0 {
		t.Fatal("unaudited certificate returned", err)
	}
	var count int
	var retire int64
	if err := s.db.QueryRow("SELECT COUNT(*),MAX(retire_at) FROM node_credentials").Scan(&count, &retire); err != nil || count != 1 || retire != 0 {
		t.Fatal("failed issuance changed credentials", count, retire, err)
	}
	if _, err := s.Authorize(b.Probe.Leaf); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TRIGGER deny_renewal"); err != nil {
		t.Fatal(err)
	}
	data, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, csr, i, "test")
	if err != nil {
		t.Fatal(err)
	}
	leaf := renewedLeaf(t, data)
	if _, err := s.db.Exec("CREATE TRIGGER deny_revoke BEFORE INSERT ON audit_events WHEN NEW.kind='certificate_revoked' BEGIN SELECT RAISE(ABORT,'full disk'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCertificate(t.Context(), b.Node.AgentID, identity.Fingerprint(leaf)); err == nil {
		t.Fatal("unaudited revocation committed")
	}
	if _, err := s.Authorize(leaf); err != nil {
		t.Fatal("failed revocation did not roll back", err)
	}
}

func TestCredentialOverlapExpiryAndDisabledRenewal(t *testing.T) {
	s, _, b, _ := taskStore(t)
	i, csr, id := testIssuer(t), renewalCSR(t), identity.RandomID()
	data, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, csr, i, "test")
	if err != nil {
		t.Fatal(err)
	}
	leaf := renewedLeaf(t, data)
	if _, err := s.db.Exec("UPDATE node_credentials SET retire_at=? WHERE generation=1", time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(b.Probe.Leaf); err == nil {
		t.Fatal("overlap expiry ignored")
	}
	if _, err := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, id, csr, i, "test"); err == nil {
		t.Fatal("retry extended overlap")
	}
	if _, err := s.Authorize(leaf); err != nil {
		t.Fatal(err)
	}
	if err := s.Disable(t.Context(), b.Node.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenewCertificate(t.Context(), leaf, i.Certificate(), identity.RandomID(), csr, i, "test"); err == nil {
		t.Fatal("disabled node renewed")
	}
	if i.calls.Load() != 1 {
		t.Fatal("unauthorized issuer invocation")
	}
}

func TestSchemaThreeCredentialMigrationPreservesExistingState(t *testing.T) {
	s, dir, b, key := taskStore(t)
	task := enqueue(t, s, b.Node.AgentID)
	envelope, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "test")
	if err != nil {
		t.Fatal(err)
	}
	var seq int64
	var hash string
	if err := s.db.QueryRow("SELECT sequence,hash FROM audit_head").Scan(&seq, &hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TABLE certificate_renewals; DROP TABLE node_credentials; PRAGMA user_version=3"); err != nil {
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
	var previous string
	if err := s.db.QueryRow("SELECT previous_hash FROM audit_events WHERE sequence=?", seq+1).Scan(&previous); err != nil || previous != hash {
		t.Fatal("migration rewrote audit prefix", err)
	}
	if _, err := s.Authorize(b.Probe.Leaf); err != nil {
		t.Fatal("legacy leaf pin lost", err)
	}
	if err := s.ConfigureSigner(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	again, err := s.Poll(t.Context(), b.Probe.Leaf, task.PolicyDigest, key, "test")
	if err != nil || !bytes.Equal(again, envelope) {
		t.Fatal("migration changed dispatched bytes", err)
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := audit.Verify(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalSerializesWithConcurrentDisablement(t *testing.T) {
	s, dir, b, _ := taskStore(t)
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	i, csr := testIssuer(t), renewalCSR(t)
	start := make(chan struct{})
	finished := make(chan error, 1)
	go func() { <-start; finished <- other.Disable(t.Context(), b.Node.AgentID) }()
	close(start)
	data, renewErr := s.RenewCertificate(t.Context(), b.Probe.Leaf, b.CA.Certificate, identity.RandomID(), csr, i, "test")
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(b.Probe.Leaf); err == nil {
		t.Fatal("disabled old credential remained authorized")
	}
	if renewErr == nil {
		if _, err := s.Authorize(renewedLeaf(t, data)); err == nil {
			t.Fatal("issuance resurrected disabled node")
		}
		var issued, disabled int64
		if err := s.db.QueryRow("SELECT sequence FROM audit_events WHERE kind='certificate_renewed'").Scan(&issued); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRow("SELECT sequence FROM audit_events WHERE kind='node_disabled'").Scan(&disabled); err != nil || issued >= disabled {
			t.Fatal("issuance committed after disablement", issued, disabled, err)
		}
	} else if i.calls.Load() != 0 {
		t.Fatal("issuer ran after disablement won the transaction", renewErr)
	}
}
