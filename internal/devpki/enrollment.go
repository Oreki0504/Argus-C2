package devpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"
)

// EnrollmentBundle keeps the offline root key in memory only. Its separate
// online issuer can sign client certificates but cannot issue subordinate CAs.
type EnrollmentBundle struct {
	CA             *Authority
	Server, Issuer Certificate
}

func NewEnrollment() (*EnrollmentBundle, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	n, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "Argus development offline root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 1}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca := &Authority{Certificate: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	b := &EnrollmentBundle{CA: ca}
	st := ServerTemplate()
	st.NotAfter = cert.NotAfter
	b.Server, err = ca.Issue(st)
	if err != nil {
		return nil, err
	}
	b.Issuer, err = ca.Issue(x509.Certificate{Subject: pkix.Name{CommonName: "Argus development probe issuer"}, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (b *EnrollmentBundle) WriteDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"ca.pem": b.CA.PEM, "server-cert.pem": b.Server.PEM, "server-key.pem": b.Server.KeyPEM, "issuer-cert.pem": b.Issuer.PEM, "issuer-key.pem": b.Issuer.KeyPEM} {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(data)
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
