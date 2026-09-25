// Package tlsconfig provides mandatory TLS 1.3 and normal X.509 verification.
package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

type Files struct{ Certificate, PrivateKey, CA string }

func load(files Files, usage x509.ExtKeyUsage) (tls.Certificate, *x509.CertPool, error) {
	certPEM, err := localfile.Read(files.Certificate, 64*1024, false)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM, err := localfile.Read(files.PrivateKey, 16*1024, true)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("invalid or mismatched certificate and private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pair.Leaf = leaf
	now := time.Now()
	if leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != usage || len(leaf.UnknownExtKeyUsage) != 0 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, nil, errors.New("invalid leaf certificate purpose or validity")
	}
	roots, err := LoadRoots(files.CA)
	return pair, roots, err
}

// LoadRoots never falls back to platform trust or trust-on-first-use.
func LoadRoots(path string) (*x509.CertPool, error) {
	caPEM, err := localfile.Read(path, 64*1024, false)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(caPEM)) > 0 {
		caPEM = bytes.TrimSpace(caPEM)
		if !bytes.HasPrefix(caPEM, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("invalid CA PEM data")
		}
		block, rest := pem.Decode(caPEM)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid CA PEM block")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("trust anchor is not a CA certificate")
		}
		roots.AddCert(ca)
		count++
		caPEM = rest
	}
	if count == 0 {
		return nil, errors.New("empty CA bundle")
	}
	return roots, nil
}

func Client(files Files, expected identity.Node, serverName string) (*tls.Config, error) {
	if expected.Validate() != nil || serverName == "" {
		return nil, errors.New("node identity and server name are required")
	}
	pair, roots, err := load(files, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	actual, err := identity.FromCertificate(pair.Leaf)
	if err != nil || actual != expected {
		return nil, errors.New("client certificate does not match local identity")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: serverName, NextProtos: []string{"http/1.1"}}, nil
}

func Server(files Files, registry identity.Authorizer) (*tls.Config, error) {
	if registry == nil {
		return nil, errors.New("node registry is required")
	}
	pair, roots, err := load(files, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{pair}, ClientCAs: roots,
		ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true,
		NextProtos: []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return errors.New("verified client certificate required")
			}
			_, err := registry.Authorize(state.PeerCertificates[0])
			return err
		},
	}, nil
}

// EnrollmentServer is for a separate, explicitly enabled enrollment listener.
// It must never replace the configuration on the probe API listener.
func EnrollmentServer(files Files) (*tls.Config, error) {
	pair, _, err := load(files, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{pair}, SessionTicketsDisabled: true,
		NextProtos: []string{"http/1.1"}}, nil
}

func EnrollmentClient(ca, serverName string) (*tls.Config, error) {
	if serverName == "" {
		return nil, errors.New("server name is required")
	}
	roots, err := LoadRoots(ca)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: serverName, NextProtos: []string{"http/1.1"}}, nil
}

// Administrator TLS is deliberately separate from mandatory probe mTLS.
func AdministrationServer(files Files) (*tls.Config, error) { return EnrollmentServer(files) }
func AdministrationClient(ca, serverName string) (*tls.Config, error) {
	return EnrollmentClient(ca, serverName)
}
