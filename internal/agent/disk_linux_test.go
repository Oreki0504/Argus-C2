//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"golang.org/x/sys/unix"
)

// The disposable systemd CI fixture supplies a dedicated 16 MiB tmpfs. Never
// fill a shared host filesystem, even if an environment variable is mis-set.
func TestFilesystemFullRecovery(t *testing.T) {
	mount := os.Getenv("ARGUS_ENOSPC_DIR")
	if mount == "" {
		t.Skip("requires a dedicated bounded tmpfs from disposable deployment CI")
	}
	if !filepath.IsAbs(mount) {
		t.Fatal("absolute mount path required")
	}
	var fs unix.Statfs_t
	var here, parent unix.Stat_t
	if e := unix.Statfs(mount, &fs); e != nil {
		t.Fatal(e)
	}
	if e := unix.Stat(mount, &here); e != nil {
		t.Fatal(e)
	}
	if e := unix.Stat(filepath.Dir(mount), &parent); e != nil {
		t.Fatal(e)
	}
	if fs.Type != unix.TMPFS_MAGIC || fs.Blocks*uint64(fs.Bsize) > 32*1024*1024 || here.Dev == parent.Dev {
		t.Fatal("refusing disk pressure outside a dedicated <=32 MiB tmpfs mount")
	}
	dir, e := os.MkdirTemp(mount, "agent-state-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	s, e := OpenState(filepath.Join(dir, "state"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	filler := filepath.Join(dir, "filler")
	calls := 0
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls++
		if _, e := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
			t.Fatal(e)
		}
		f, e := os.OpenFile(filler, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		block := make([]byte, 4096)
		for {
			if _, e = f.Write(block); e != nil {
				break
			}
		}
		f.Close()
		if !errors.Is(e, unix.ENOSPC) {
			t.Fatal("expected filesystem ENOSPC", e)
		}
		return goodPayload(), nil
	}}
	job := task("disk-full")
	if _, e = engine.Process(t.Context(), job, start); e == nil {
		t.Fatal("result unexpectedly persisted on full filesystem")
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	if _, e = engine.Process(t.Context(), job, start); e == nil {
		t.Fatal("unresolved storage failure ignored")
	}
	if calls != 1 {
		t.Fatal("collector repeated on full disk")
	}
	if e = os.Remove(filler); e != nil {
		t.Fatal(e)
	}
	r, e := engine.Process(t.Context(), job, start)
	if e != nil || r.Status != protocol.Unknown || calls != 1 {
		t.Fatal("storage recovery reran or lost result", r, e, calls)
	}
}
