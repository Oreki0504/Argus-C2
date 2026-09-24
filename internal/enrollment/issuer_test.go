package enrollment

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
)

func TestCSRProofAndScope(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSR(der)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 1
	if _, err := ParseCSR(tampered); err == nil {
		t.Fatal("CSR signature ignored")
	}
	for _, template := range []x509.CertificateRequest{{Subject: pkix.Name{CommonName: "chosen-node"}}, {DNSNames: []string{"localhost"}}} {
		bad, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseCSR(bad); err == nil {
			t.Fatal("CSR supplied identity accepted")
		}
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCSR(bad); err == nil {
		t.Fatal("unsupported CSR key accepted")
	}
	b, err := devpki.NewEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "pki")
	if err := b.WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	i, err := LoadIssuer(filepath.Join(dir, "issuer-cert.pem"), filepath.Join(dir, "issuer-key.pem"), filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := i.CheckTransport(b.Server.Leaf); err != nil {
		t.Fatal(err)
	}
	if err := i.CheckTransport(b.Issuer.Leaf); err == nil {
		t.Fatal("issuer key reused for transport")
	}
	if _, _, err := i.Issue(nil, identity.New()); err == nil {
		t.Fatal("nil CSR accepted")
	}
	n := identity.New()
	chain, cert, err := i.Issue(csr, n)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := identity.FromCertificate(cert)
	if err != nil || actual != n || cert.IsCA || cert.NotAfter.After(time.Now().Add(12*time.Hour)) {
		t.Fatal("invalid issued identity", err)
	}
	if string(cert.PublicKey.(ed25519.PublicKey)) != string(key.Public().(ed25519.PublicKey)) {
		t.Fatal("server replaced probe public key")
	}
	block, rest := pem.Decode(chain)
	if block == nil {
		t.Fatal("missing leaf")
	}
	block, rest = pem.Decode(rest)
	if block == nil || len(rest) != 0 {
		t.Fatal("missing issuing chain")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-key.pem")); !os.IsNotExist(err) {
		t.Fatal("offline root key persisted")
	}
	if err := b.WriteDir(dir); err == nil {
		t.Fatal("development credentials overwritten")
	}
	if _, err := LoadIssuer(filepath.Join(dir, "server-cert.pem"), filepath.Join(dir, "server-key.pem"), filepath.Join(dir, "ca.pem")); err == nil {
		t.Fatal("transport credentials accepted as issuer")
	}
}

func FuzzParseCSR(f *testing.F) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	f.Add(der)
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		csr, err := ParseCSR(data)
		if err == nil {
			if err := csr.CheckSignature(); err != nil {
				t.Fatal("CSR with invalid signature accepted")
			}
		}
	})
}
