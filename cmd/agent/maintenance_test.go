package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestMaintenanceConfirmationAndExport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, e := agent.OpenState(dir, "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	job := protocol.Task{ID: "task", NodeID: "node", Type: protocol.SystemInfo, Params: json.RawMessage(`{}`), Status: protocol.Accepted, CreatedAt: time.Now().Unix(), DispatchExpiresAt: time.Now().Unix() + 60, ExecutionTimeoutMS: 1000, ResultDueAt: time.Now().Unix() + 120}
	engine := agent.Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		return json.RawMessage(`{"available":false,"os":"linux","architecture":"amd64","hostname":"","kernel":"","boot_time":0}`), nil
	}}
	if _, e = engine.Process(t.Context(), job, func(context.Context, string) error { return nil }); e != nil {
		t.Fatal(e)
	}
	for _, input := range []string{"no\n", "other\n", ""} {
		var output, diagnostics bytes.Buffer
		if e = maintain(t.Context(), s, "result-discard", job.ID, "", "", "", strings.NewReader(input), &output, &diagnostics); e == nil {
			t.Fatal("unconfirmed deletion")
		}
		if _, e = s.ResultBytes(t.Context(), job.ID); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(diagnostics.String(), "Server state: unknown") {
			t.Fatal("offline state not disclosed")
		}
	}
	var output, diagnostics bytes.Buffer
	export := filepath.Join(t.TempDir(), "result.json")
	if e = maintain(t.Context(), s, "result-export", job.ID, "", export, "", strings.NewReader(""), &output, &diagnostics); e != nil {
		t.Fatal(e)
	}
	stat, e := os.Stat(export)
	if e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "windows" && stat.Mode().Perm() != 0600 {
		t.Fatal("export permissions")
	}
	if e = maintain(t.Context(), s, "result-export", job.ID, "", export, "", strings.NewReader(""), &output, &diagnostics); e == nil {
		t.Fatal("export overwritten")
	}
	if e = maintain(t.Context(), s, "result-discard", job.ID, "", "", "wrong", strings.NewReader(job.ID), &output, &diagnostics); e == nil {
		t.Fatal("wrong confirmation accepted")
	}
	if e = maintain(t.Context(), s, "result-discard", job.ID, "", "", job.ID, strings.NewReader(""), &output, &diagnostics); e != nil {
		t.Fatal(e)
	}
	record, e := s.Delivery(t.Context(), job.ID)
	if e != nil || record.Delivery != "discarded" {
		t.Fatal(record, e)
	}
	if e = maintain(t.Context(), s, "result-retry", job.ID, "", "", "", strings.NewReader(""), &output, &diagnostics); e == nil {
		t.Fatal("discard retried")
	}
}
