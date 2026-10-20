package tlsconfig_test

import (
	"bytes"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func TestStrictCertificateBundle(t *testing.T) {
	ca, err := devpki.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{nil, []byte("junk"), append([]byte("junk\n"), ca.PEM...), append(append([]byte{}, ca.PEM...), []byte("junk")...), append(append([]byte{}, ca.PEM...), ca.PEM...), append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), ca.PEM...), bytes.Repeat([]byte("x"), 65537)} {
		if _, err := tlsconfig.ParseCertificates(b); err == nil {
			t.Fatal("accepted malformed/duplicate/oversized PEM")
		}
	}
	var bundle []byte
	for i := 0; i < tlsconfig.MaxCertificates+1; i++ {
		ca, err := devpki.NewAuthority()
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, ca.PEM...)
		_, err = tlsconfig.ParseCertificates(bundle)
		if (err == nil) != (i < tlsconfig.MaxCertificates) {
			t.Fatal("wrong count bound", i, err)
		}
	}
}

func FuzzCertificateBundle(f *testing.F) {
	ca, err := devpki.NewAuthority()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ca.PEM)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\ninvalid"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		certs, err := tlsconfig.ParseCertificates(b)
		if err == nil && (len(certs) == 0 || len(certs) > tlsconfig.MaxCertificates || len(b) > 65536) {
			t.Fatal("unbounded certificate bundle")
		}
	})
}
