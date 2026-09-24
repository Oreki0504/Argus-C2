package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestSeparateKeyGenerationAndStrictLoading(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "task-private.pem")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	private, err := LoadPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublic(filepath.Join(dir, "task-public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, private.Public().(ed25519.PublicKey)) {
		t.Fatal("key mismatch")
	}
	if err := Generate(dir); err == nil {
		t.Fatal("overwrote key directory")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing key changed")
	}
	spki, _ := x509.MarshalPKIXPublicKey(pub)
	if err := Distinct(private, &x509.Certificate{RawSubjectPublicKeyInfo: spki}); err == nil {
		t.Fatal("reused signing key allowed")
	}
	if err := os.WriteFile(path, append(before, before...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(path); err == nil {
		t.Fatal("multiple PEM keys allowed")
	}
}
