// Package enrollment implements one enrollment authority and ordinary X.509 renewal.
package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

type Issuer struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
	Lifetime    time.Duration
}

func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n.Add(n, big.NewInt(1))
}
func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func KeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func Load(certPath, keyPath string) (*Issuer, error) {
	c, e := localfile.Read(certPath, 16384, false)
	if e != nil {
		return nil, e
	}
	k, e := localfile.Read(keyPath, 16384, true)
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair(c, k)
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return nil, errors.New("invalid enrollment authority")
	}
	return &Issuer{cert, key, 30 * 24 * time.Hour}, nil
}
func ParseCSR(b []byte) (*x509.CertificateRequest, error) {
	if len(b) == 0 || len(b) > 4096 {
		return nil, errors.New("invalid CSR size")
	}
	c, e := x509.ParseCertificateRequest(b)
	if e != nil {
		return nil, e
	}
	if e = c.CheckSignature(); e != nil {
		return nil, e
	}
	key, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || len(c.Extensions) > 0 || len(c.Subject.Names) > 0 || len(c.Attributes) > 0 {
		return nil, errors.New("CSR must contain only a P-256 public key")
	}
	return c, nil
}
func (i *Issuer) Issue(csr []byte, id string) (string, *x509.Certificate, error) {
	c, e := ParseCSR(csr)
	if e != nil {
		return "", nil, e
	}
	now := time.Now()
	until := now.Add(i.Lifetime)
	if until.After(i.Certificate.NotAfter) {
		until = i.Certificate.NotAfter
	}
	if now.Before(i.Certificate.NotBefore) || until.Sub(now) < time.Hour {
		return "", nil, errors.New("enrollment authority expires too soon")
	}
	t := &x509.Certificate{SerialNumber: serial(), NotBefore: now.Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI(id)}}
	der, e := x509.CreateCertificate(rand.Reader, t, i.Certificate, c.PublicKey, i.Key)
	if e != nil {
		return "", nil, e
	}
	cert, e := x509.ParseCertificate(der)
	return string(certPEM(der)), cert, e
}
func CSR(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
}

// Initialize writes a single CA and a distinct server leaf. Existing files are never overwritten.
func Initialize(dir string, hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("server hostnames are required")
	}
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Argus fleet CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if e != nil {
		return e
	}
	root, e = x509.ParseCertificate(der)
	if e != nil {
		return e
	}
	rootKey, e := KeyPEM(key)
	if e != nil {
		return e
	}
	serverKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: serial(), NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range hosts {
		if h == "" {
			return errors.New("empty server name")
		}
		if ip := net.ParseIP(h); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, h)
		}
	}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, &serverKey.PublicKey, key)
	if e != nil {
		return e
	}
	serverPEM, e := KeyPEM(serverKey)
	if e != nil {
		return e
	}
	for _, f := range []struct {
		name string
		b    []byte
	}{{"ca.pem", certPEM(der)}, {"ca-key.pem", rootKey}, {"server.pem", certPEM(leafDER)}, {"server-key.pem", serverPEM}} {
		out, e := os.OpenFile(filepath.Join(dir, f.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = out.Write(f.b)
		ce := out.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	return nil
}
