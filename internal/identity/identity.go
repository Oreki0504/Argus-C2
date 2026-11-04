// Package identity contains identifiers and certificate fingerprints, not a PKI lifecycle.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
)

func RandomID() string { return rand.Text() }
func Hex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func Valid(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func Fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}
func URI(id string) *url.URL { return &url.URL{Scheme: "argus", Host: "nodes", Path: "/" + id} }
func FromCertificate(c *x509.Certificate) (string, error) {
	if c == nil || c.IsCA || len(c.URIs) != 1 || c.URIs[0] == nil || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return "", errors.New("invalid node certificate")
	}
	id := c.URIs[0].Path
	if len(id) < 2 {
		return "", errors.New("missing node identity")
	}
	id = id[1:]
	if !Valid(id) || c.URIs[0].String() != URI(id).String() {
		return "", errors.New("invalid node identity")
	}
	return id, nil
}
