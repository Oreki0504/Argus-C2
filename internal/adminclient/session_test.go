package adminclient

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/state"
)

func TestPrivateSessionPersistenceAndOriginBinding(t *testing.T) {
	c := &Client{Origin: "https://127.0.0.1:8445", CAHash: strings.Repeat("a", 64)}
	v := state.Login{Token: strings.Repeat("b", 64), User: state.User{ID: strings.Repeat("c", 32), Username: "operator", Role: "Admin", Enabled: true}, ExpiresAt: 2000000000, IdleSeconds: 1800}
	dir := filepath.Join(t.TempDir(), "session")
	if err := PrepareSession(dir); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveSession(dir, v); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveSession(dir, v); err == nil {
		t.Fatal("existing session overwritten")
	}
	if err := PrepareSession(dir); err == nil {
		t.Fatal("login overwrites active credentials")
	}
	got, err := c.LoadSession(dir)
	if err != nil || got.Token != v.Token {
		t.Fatal("credential roundtrip", err)
	}
	other := *c
	other.Origin = "https://127.0.0.1:9445"
	if _, err := other.LoadSession(dir); err == nil {
		t.Fatal("session sent to different server")
	}
	other = *c
	other.CAHash = strings.Repeat("d", 64)
	if _, err := other.LoadSession(dir); err == nil {
		t.Fatal("session used with replacement trust")
	}
	path := filepath.Join(dir, "session.bin")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if bytes.Contains(b, []byte(v.Token)) {
			t.Fatal("Windows token stored in plaintext")
		}
		b[len(b)/2] ^= 1
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.LoadSession(dir); err == nil {
			t.Fatal("corrupted DPAPI data accepted")
		}
	} else {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := c.LoadSession(dir); err == nil {
			t.Fatal("public session file accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := c.LoadSession(dir); err == nil {
			t.Fatal("public session directory accepted")
		}
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := ForgetSession(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("local session not forgotten")
	}
}
