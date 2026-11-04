package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestCSRRejectsRequestedAuthority(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, template := range []*x509.CertificateRequest{{Subject: pkix.Name{CommonName: "choose-my-identity"}}, {DNSNames: []string{"other.example"}}} {
		b, e := x509.CreateCertificateRequest(rand.Reader, template, key)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ParseCSR(b); e == nil {
			t.Fatal("CSR authority accepted")
		}
	}
	b, e := CSR(key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseCSR(b); e != nil {
		t.Fatal(e)
	}
}
func FuzzParseCSR(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := CSR(key)
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, e := ParseCSR(b); e == nil {
			if e = c.CheckSignature(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
