package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func TestSignerInspectionDoesNotRequireOrCreateOutput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "key")
	var output bytes.Buffer
	if err := run([]string{"-action", "generate", "-out", dir}, &output); err != nil {
		t.Fatal(err)
	}
	args := []string{"-action", "inspect", "-current", filepath.Join(dir, "task-public.pem")}
	if err := run(args, &output); !errors.Is(err, errUnhealthy) {
		t.Fatal("legacy expiry should warn", err)
	}
	var report signing.HealthReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.State != "warning" || report.Keys[0].State != "no_expiry" {
		t.Fatal(report, err)
	}
	for _, bad := range [][]string{
		append(append([]string{}, args...), "-out", filepath.Join(dir, "unexpected")),
		append(append([]string{}, args...), "-warn-before", "bad-duration"),
		{"-action", "generate", "-out", filepath.Join(dir, "unexpected"), "-selected-key-id", ""},
		{"-unknown"},
	} {
		output.Reset()
		if err := run(bad, &output); err == nil || errors.Is(err, errUnhealthy) || output.Len() != 0 {
			t.Fatal("invalid usage confused with health warning", err)
		}
	}
}
