//go:build linux

package sshaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func TestBaselineIsLocalAndSensitiveInputHasNoDigest(t *testing.T) {
	dir := t.TempDir()
	line, _ := publicLine(t)
	content := []byte(line + "\n")
	hash := sha256.Sum256(content)
	mapping := resources.SSHFile{ID: "keys", Kind: "authorized_keys", BaseDir: dir, RelativePath: "authorized_keys", OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()), MaxBytes: 4096, BaselineSHA256: hex.EncodeToString(hash[:])}
	profile := resources.SSHProfile{ID: "user", Files: []resources.SSHFile{mapping}}
	for _, tc := range []struct {
		data             []byte
		status, baseline string
	}{
		{content, "ok", "match"}, {append(append([]byte{}, content...), []byte("# changed\n")...), "ok", "changed"},
		{[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nprivate\n"), "sensitive_content", "unavailable"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), tc.data, 0600); err != nil {
			t.Fatal(err)
		}
		report, err := Collect(t.Context(), profile)
		if err != nil {
			t.Fatal(err)
		}
		f := report.Files[0]
		if f.Status != tc.status || f.Baseline != tc.baseline {
			t.Fatal(f)
		}
		if tc.status == "sensitive_content" && (f.SHA256 != "" || len(f.Keys) > 0) {
			t.Fatal("sensitive data summarized")
		}
		if profile.Files[0].BaselineSHA256 != mapping.BaselineSHA256 {
			t.Fatal("baseline changed automatically")
		}
		b, _ := json.Marshal(report)
		if _, err := protocol.DecodeSSHReport(b, time.Now().Unix()); err != nil {
			t.Fatal("collector/schema disagreement", err)
		}
	}
}
