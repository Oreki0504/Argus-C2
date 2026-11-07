package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"time"
)

// ConsoleServer uses a browser certificate independently of the Fleet CA and
// requests no client certificates. Browser trust is configured by the operator.
func ConsoleServer(cert, key, origin, fleetCA string) (*tls.Config, error) {
	if err := ValidateURL(origin); err != nil {
		return nil, err
	}
	u, _ := url.Parse(origin)
	pair, err := Pair(cert, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if leaf.IsCA || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, errors.New("invalid Console leaf certificate validity")
	}
	if err = leaf.VerifyHostname(u.Hostname()); err != nil {
		return nil, err
	}
	serverUsage := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			serverUsage = true
		}
	}
	if !serverUsage {
		return nil, errors.New("Console certificate does not permit server authentication")
	}
	roots, err := Roots(fleetCA)
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(c)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		return nil, errors.New("Console certificate must be independent of the Fleet CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.NoClientCert, SessionTicketsDisabled: true}, nil
}
