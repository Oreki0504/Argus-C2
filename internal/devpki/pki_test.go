package devpki

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDevelopmentCredentialsDoNotOverwrite(t *testing.T) {
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "pki")
	if err := b.WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "probe-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.WriteDir(dir); err == nil {
		t.Fatal("reused existing output directory")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "probe-key.pem"))
	if string(before) != string(after) {
		t.Fatal("modified existing key")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 7 {
		t.Fatal("unexpected credential output")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-key.pem")); !os.IsNotExist(err) {
		t.Fatal("CA private key was persisted")
	}
}
