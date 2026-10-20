package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignerHealth(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, "legacy")
	if err := Generate(legacyDir); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(legacyDir, "task-public.pem")
	now := time.Now().Truncate(time.Second)
	r, err := Inspect(legacyPath, "", time.Hour, now)
	if err != nil || r.State != "warning" || r.Keys[0].State != "no_expiry" {
		t.Fatal(r, err)
	}
	legacy, err := LoadPublic(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := Stage(legacy, nil, pub, now, now.Add(time.Hour).Unix(), now.Add(30*24*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	data, err := trust.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, selected string
		at             time.Time
		window         time.Duration
		state          string
	}{
		{"valid", KeyID(pub), now, 0, "ok"},
		{"warning", KeyID(pub), now, 2 * time.Hour, "warning"},
		{"old expired", KeyID(pub), now.Add(time.Hour), 0, "warning"},
		{"selected expired", KeyID(legacy), now.Add(time.Hour), 0, "blocked"},
		{"all expired", "", now.Add(30 * 24 * time.Hour), 0, "blocked"},
		{"not yet valid", "", now.Add(-24 * time.Hour), 0, "blocked"},
		{"unknown selected", "unknown", now, 0, "blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Inspect(path, tc.selected, tc.window, tc.at)
			if err != nil || r.State != tc.state {
				t.Fatal(tc.state, r, err)
			}
		})
	}
	if _, err := Inspect(path, "", -time.Second, now); err == nil {
		t.Fatal("negative warning window")
	}
	if _, err := Inspect(path, "", 91*24*time.Hour, now); err == nil {
		t.Fatal("excessive warning window")
	}
}
