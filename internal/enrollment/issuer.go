// Package enrollment issues narrowly scoped probe identities from signed CSRs.
package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/signing"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

type Issuer struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  []byte
}

func (i *Issuer) CheckTaskKey(key ed25519.PrivateKey) error { return signing.Distinct(key, i.cert) }

func LoadIssuer(certPath, keyPath, caPath string) (*Issuer, error) {
	certPEM, err := localfile.Read(certPath, 16384, false)
	if err != nil {
		return nil, err
	}
	keyPEM, err := localfile.Read(keyPath, 16384, true)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("invalid issuer credentials")
	}
	if len(pair.Certificate) != 1 {
		return nil, errors.New("expected one issuing CA certificate")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(ed25519.PrivateKey)
	if !ok || !cert.IsCA || !cert.BasicConstraintsValid || !cert.MaxPathLenZero || cert.KeyUsage&x509.KeyUsageCertSign == 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return nil, errors.New("issuer must be a non-root, client-auth-only Ed25519 CA with path length zero")
	}
	roots, err := tlsconfig.LoadRoots(caPath)
	if err != nil {
		return nil, err
	}
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 || len(chains[0]) < 2 {
		return nil, errors.New("issuer must chain to the separately provisioned root CA")
	}
	return &Issuer{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}, nil
}

func ParseCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > 2048 {
		return nil, errors.New("invalid CSR size")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errors.New("invalid CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("invalid CSR proof of possession")
	}
	// x509 exposes only attributes it understands. Inspect the signed ASN.1
	// sequence as well so unknown attributes cannot bypass the empty-CSR rule.
	var info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"optional,tag:0"`
	}
	rest, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &info)
	if err != nil || len(rest) != 0 || info.Version != 0 || len(info.Attributes) != 0 || !bytes.Equal(csr.RawSubject, []byte{0x30, 0x00}) {
		return nil, errors.New("CSR subject and attributes must be empty")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok || len(csr.Subject.Names) != 0 || len(csr.Extensions) != 0 || len(csr.Attributes) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, errors.New("CSR must contain only an Ed25519 public key")
	}
	return csr, nil
}

func (i *Issuer) Issue(csr *x509.CertificateRequest, n identity.Node) ([]byte, *x509.Certificate, error) {
	if csr == nil {
		return nil, nil, errors.New("CSR is required")
	}
	checked, err := ParseCSR(csr.Raw)
	if err != nil {
		return nil, nil, err
	}
	u, err := n.URI()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	if now.Before(i.cert.NotBefore) || !now.Add(time.Minute).Before(i.cert.NotAfter) {
		return nil, nil, errors.New("issuing CA is outside its usable validity window")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	serial.Add(serial, big.NewInt(1))
	expires := now.Add(12 * time.Hour)
	if expires.After(i.cert.NotAfter) {
		expires = i.cert.NotAfter
	}
	notBefore := now.Add(-time.Minute)
	if notBefore.Before(i.cert.NotBefore) {
		notBefore = i.cert.NotBefore
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: notBefore, NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, checked.PublicKey, i.key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, i.pem...)
	return chain, cert, nil
}

// CheckTransport compares key material, not filenames or certificate subjects.
func (i *Issuer) CheckTransport(cert *x509.Certificate) error {
	if cert == nil || bytes.Equal(i.cert.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		return errors.New("transport and certificate-issuance keys must be distinct")
	}
	return nil
}
