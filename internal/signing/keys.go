package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

func readKey(path, kind string, secret bool) ([]byte, error) {
	b, err := localfile.Read(path, 4096, secret)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	if !bytes.HasPrefix(b, []byte("-----BEGIN "+kind+"-----")) {
		return nil, errors.New("invalid signing key PEM")
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one signing key")
	}
	return block.Bytes, nil
}
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := readKey(path, "PRIVATE KEY", true)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("task signing requires Ed25519")
	}
	return key, nil
}
func LoadPublic(path string) (ed25519.PublicKey, error) {
	b, err := readKey(path, "PUBLIC KEY", false)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("task verification requires Ed25519")
	}
	return key, nil
}
func Distinct(key ed25519.PrivateKey, cert *x509.Certificate) error {
	if cert == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("transport/issuer certificate is required")
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	if bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return errors.New("task signing must use a separate key")
	}
	return nil
}

// Generate refuses existing directories and never prints private material.
func Generate(dir string) error {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	secret, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	public, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for _, item := range []struct {
		name, kind string
		data       []byte
	}{
		{"task-private.pem", "PRIVATE KEY", secret}, {"task-public.pem", "PUBLIC KEY", public},
	} {
		f, err := os.OpenFile(filepath.Join(dir, item.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		err = pem.Encode(f, &pem.Block{Type: item.kind, Bytes: item.data})
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
