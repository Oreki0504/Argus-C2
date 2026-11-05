package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func TestServerLeafRotationPreservesAgentIdentityAndResults(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job, _ := pendingResult(t, f, r)
	old := nodeCertificate(t, r)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(200), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.issuer.Certificate, &key.PublicKey, f.issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := enrollment.KeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	address := f.server.Listener.Addr().String()
	f.server.Close()
	if err = os.WriteFile(filepath.Join(f.dir, "server-key.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	f.start(address)
	if err = r.Step(t.Context()); err != nil {
		t.Fatal("existing agent could not reconnect after leaf rotation", err)
	}
	record, err := r.Engine.State.Delivery(t.Context(), job.ID)
	if err != nil || record.Delivery != "acknowledged" {
		t.Fatal(record, err)
	}
	current := nodeCertificate(t, r)
	if !current.Equal(old) {
		t.Fatal("server rotation changed node identity")
	}
	f.call(f.readToken, "GET", "/v1/health", nil)
	leaf.NotAfter = now.Add(-time.Second)
	der, err = x509.CreateCertificate(rand.Reader, leaf, f.issuer.Certificate, &key.PublicKey, f.issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = transport.Server(filepath.Join(f.dir, "server.pem"), filepath.Join(f.dir, "server-key.pem"), filepath.Join(f.dir, "ca.pem")); err == nil {
		t.Fatal("expired replacement accepted at startup")
	}
}
