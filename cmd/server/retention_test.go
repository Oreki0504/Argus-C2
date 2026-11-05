package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

func TestPruneCommandDefaultPreviewAndExplicitBackup(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	s, err := database.Open(state, true)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Maintenance must work without loading service-only credentials.
	missing := filepath.Join(dir, "unavailable-credential")
	c := config.Server{Listen: "127.0.0.1:8443", StateDir: state, Certificate: missing, PrivateKey: missing, CA: missing, IssuerKey: missing, Admins: missing}
	file := filepath.Join(dir, "server.json")
	if err = writeJSON(file, c); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = pruneCommand([]string{"-config", file}, &out); err != nil {
		t.Fatal(err)
	}
	var p database.PruneReport
	if err = json.Unmarshal(out.Bytes(), &p); err != nil || p.RetainDays != 30 || p.Limit != 200 || p.Applied || p.Items == nil {
		t.Fatal(p, err)
	}
	backup := filepath.Join(dir, "snapshot.db")
	for _, args := range [][]string{{"-apply"}, {"-backup", backup}, {"-retain-days", "0"}, {"-limit", "1001"}, {"unexpected"}} {
		if err = pruneCommand(append([]string{"-config", file}, args...), &bytes.Buffer{}); err == nil {
			t.Fatal("unsafe arguments accepted", args)
		}
	}
	if _, err = os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("preview created backup", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("private-directory apply semantics are Unix-only")
	}
	out.Reset()
	if err = pruneCommand([]string{"-config", file, "-apply", "-backup", backup}, &out); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(out.Bytes(), &p); err != nil || !p.Applied || p.Backup != backup {
		t.Fatal(p, err)
	}
	if err = pruneCommand([]string{"-config", file, "-apply", "-backup", backup}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing backup overwritten")
	}
}
