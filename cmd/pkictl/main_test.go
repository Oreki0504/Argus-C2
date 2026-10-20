package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func TestInspectExitCodesAndReadOnlyFlags(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	var output bytes.Buffer
	if code, err := run([]string{"-action", "root", "-out", root, "-lifetime", "48h"}, &output); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	ca := filepath.Join(root, "root-cert.pem")
	args := []string{"-action", "inspect", "-profile", "root", "-cert", ca, "-ca", ca}
	for _, tc := range []struct {
		window string
		code   int
		state  string
	}{{"0s", 0, "ok"}, {"240h", 2, "warning"}} {
		output.Reset()
		code, err := run(append(append([]string{}, args...), "-warn-before", tc.window), &output)
		if code != tc.code || err != nil {
			t.Fatal(code, err)
		}
		var report tlsconfig.HealthReport
		if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.State != tc.state {
			t.Fatal(report, err)
		}
		if bytes.Contains(output.Bytes(), []byte("PRIVATE KEY")) {
			t.Fatal("secret output")
		}
	}
	request := filepath.Join(dir, "request")
	if code, err := run([]string{"-action", "request", "-out", request}, &output); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	output.Reset()
	code, err := run(append(append([]string{}, args...), "-key", filepath.Join(request, "key.pem")), &output)
	if code != 2 || err != nil {
		t.Fatal("mismatched key must produce blocked JSON", code, err)
	}
	never := filepath.Join(dir, "never-created")
	for _, bad := range [][]string{
		append(append([]string{}, args...), "-out", never),
		{"-action", "request", "-out", never, "-lifetime", "0"},
		{"-action", "root", "-out", never, "-warn-before", "0s"},
		append(append([]string{}, args...), "-identity", "unrelated"),
		append(append([]string{}, args...), "-warn-before", "bad-duration"),
		{"-unknown"},
	} {
		output.Reset()
		if code, err := run(bad, &output); code != 1 || err == nil || output.Len() != 0 {
			t.Fatal("bad usage did not fail distinctly", code, err)
		}
		if _, err := os.Stat(never); !os.IsNotExist(err) {
			t.Fatal("inspection or invalid flags created output")
		}
	}
}
