// Package devpki provisions short-lived, loopback-only development certificates.
// It is never used by the server to issue identities over the network.
package devpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
)

type Authority struct {
	Certificate *x509.Certificate
	key         ed25519.PrivateKey
	PEM         []byte
}
type Certificate struct {
	PEM, KeyPEM []byte
	TLS         tls.Certificate
	Leaf        *x509.Certificate
}
type Bundle struct {
	CA            *Authority
	Server, Probe Certificate
	Node          identity.Node
}

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}
func NewAuthority() (*Authority, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	n, err := serial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: n, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{Certificate: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func (ca *Authority) Issue(template x509.Certificate) (Certificate, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Certificate{}, err
	}
	template.SerialNumber, err = serial()
	if err != nil {
		return Certificate{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, pub, ca.key)
	if err != nil {
		return Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Certificate{}, err
	}
	pair.Leaf = leaf
	return Certificate{PEM: certPEM, KeyPEM: keyPEM, TLS: pair, Leaf: leaf}, nil
}

func ClientTemplate(node identity.Node) (x509.Certificate, error) {
	u, err := node.URI()
	if err != nil {
		return x509.Certificate{}, err
	}
	return x509.Certificate{NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}, nil
}
func ServerTemplate() x509.Certificate {
	return x509.Certificate{NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
}
func New() (*Bundle, error) {
	ca, err := NewAuthority()
	if err != nil {
		return nil, err
	}
	b := &Bundle{CA: ca, Node: identity.New()}
	b.Server, err = ca.Issue(ServerTemplate())
	if err != nil {
		return nil, err
	}
	template, err := ClientTemplate(b.Node)
	if err != nil {
		return nil, err
	}
	b.Probe, err = ca.Issue(template)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (b *Bundle) Registration() identity.Registration {
	return identity.Registration{AgentID: b.Node.AgentID, EnrollmentEpoch: b.Node.EnrollmentEpoch, CertificateSHA256: identity.Fingerprint(b.Probe.Leaf), Enabled: true}
}

// WriteDir refuses an existing output directory. The CA private key is never
// written. Partial failures leave the new directory for local inspection.
func (b *Bundle) WriteDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	node, err := json.MarshalIndent(b.Node, "", "  ")
	if err != nil {
		return err
	}
	registry, err := json.MarshalIndent(struct {
		Agents []identity.Registration `json:"agents"`
	}{[]identity.Registration{b.Registration()}}, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{"ca.pem": b.CA.PEM, "server-cert.pem": b.Server.PEM, "server-key.pem": b.Server.KeyPEM, "probe-cert.pem": b.Probe.PEM, "probe-key.pem": b.Probe.KeyPEM, "identity.json": node, "registry.json": registry}
	for name, contents := range files {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(contents)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
