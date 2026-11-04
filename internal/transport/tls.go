// Package transport configures standard Go HTTPS. It implements no crypto protocol.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

func Roots(path string) (*x509.CertPool, error) {
	b, e := localfile.Read(path, 65536, false)
	if e != nil {
		return nil, e
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA bundle")
	}
	return p, nil
}
func Pair(cert, key string) (tls.Certificate, error) {
	c, e := localfile.Read(cert, 65536, false)
	if e != nil {
		return tls.Certificate{}, e
	}
	k, e := localfile.Read(key, 16384, true)
	if e != nil {
		return tls.Certificate{}, e
	}
	return tls.X509KeyPair(c, k)
}
func Server(cert, key, ca string) (*tls.Config, error) {
	pair, e := Pair(cert, key)
	if e != nil {
		return nil, e
	}
	roots, e := Roots(ca)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, e
		}
		intermediates.AddCert(c)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return nil, e
	}
	if leaf.IsCA {
		return nil, errors.New("server credential must be a leaf certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven, SessionTicketsDisabled: true}, nil
}
func Client(ca, cert, key string) (*http.Client, error) {
	roots, e := Roots(ca)
	if e != nil {
		return nil, e
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if cert != "" {
		pair, e := Pair(cert, key)
		if e != nil {
			return nil, e
		}
		config.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{TLSClientConfig: config, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 35 * time.Second, MaxResponseHeaderBytes: 16384}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are disabled") }}, nil
}
func ValidateURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("server URL must be an HTTPS origin")
	}
	return nil
}
