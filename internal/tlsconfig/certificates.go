package tlsconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

const MaxCertificates = 8

// ParseCertificates accepts only bounded certificate PEM blocks, without
// skipped prefixes, private material, duplicate certificates or trailing data.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	if len(data) > 64*1024 {
		return nil, errors.New("certificate bundle exceeds size limit")
	}
	var certificates []*x509.Certificate
	seen := map[string]bool{}
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("invalid certificate PEM data")
		}
		const footer = "-----END CERTIFICATE-----"
		end := bytes.Index(data, []byte(footer))
		if end < 0 {
			return nil, errors.New("missing certificate PEM footer")
		}
		end += len(footer)
		block, trailing := pem.Decode(data[:end])
		rest := data[end:]
		if block == nil || len(bytes.TrimSpace(trailing)) != 0 || bytes.Count(data[:end], []byte("-----BEGIN")) != 1 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) >= MaxCertificates {
			return nil, errors.New("invalid or excessive certificate blocks")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		if seen[string(cert.Raw)] {
			return nil, errors.New("duplicate certificate")
		}
		seen[string(cert.Raw)] = true
		certificates = append(certificates, cert)
		data = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("empty certificate bundle")
	}
	return certificates, nil
}

func LoadCertificates(path string) ([]*x509.Certificate, error) {
	b, err := localfile.Read(path, 64*1024, false)
	if err != nil {
		return nil, err
	}
	return ParseCertificates(b)
}

func CheckIssuerProfile(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("issuer certificate required")
	}
	_, ed := cert.PublicKey.(ed25519.PublicKey)
	if !ed || !cert.IsCA || !cert.BasicConstraintsValid || !cert.MaxPathLenZero || cert.KeyUsage&x509.KeyUsageCertSign == 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return errors.New("issuer must be a non-root, client-auth-only Ed25519 CA with path length zero")
	}
	return nil
}
