//go:build linux

package saferead

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/resources"
	"golang.org/x/sys/unix"
)

func mapped(t *testing.T) resources.SSHFile {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return resources.SSHFile{ID: "keys", Kind: "authorized_keys", BaseDir: dir, RelativePath: "authorized_keys", OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()), MaxBytes: 1024}
}
func put(t *testing.T, f resources.SSHFile, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.BaseDir, f.RelativePath), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestSafeFileSnapshotAndBoundaries(t *testing.T) {
	for _, name := range []string{"ok", "missing", "oversize", "hardlink", "symlink", "magiclink", "fifo", "directory", "gid", "writable_parent", "permission"} {
		t.Run(name, func(t *testing.T) {
			f := mapped(t)
			path := filepath.Join(f.BaseDir, f.RelativePath)
			want := "ok"
			switch name {
			case "ok":
				put(t, f, "approved")
			case "missing":
				want = "missing"
			case "oversize":
				put(t, f, strings.Repeat("x", 1025))
				want = "too_large"
			case "hardlink":
				put(t, f, "approved")
				if err := os.Link(path, path+".other"); err != nil {
					t.Fatal(err)
				}
				want = "unsafe_type"
			case "symlink":
				other := filepath.Join(t.TempDir(), "secret")
				if err := os.WriteFile(other, []byte("secret"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
				want = "unsafe_path"
			case "magiclink":
				other, err := os.CreateTemp(t.TempDir(), "secret")
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if err := os.Symlink(fmt.Sprintf("/proc/self/fd/%d", other.Fd()), path); err != nil {
					t.Fatal(err)
				}
				want = "unsafe_path"
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				want = "unsafe_type"
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				want = "unsafe_type"
			case "gid":
				put(t, f, "approved")
				f.OwnerGID++
				want = "owner_mismatch"
			case "writable_parent":
				put(t, f, "approved")
				if err := os.Chmod(f.BaseDir, 0777); err != nil {
					t.Fatal(err)
				}
				want = "permission_denied"
			case "permission":
				if os.Geteuid() == 0 {
					t.Skip("access denial requires a non-root test user")
				}
				put(t, f, "approved")
				if err := os.Chmod(path, 0000); err != nil {
					t.Fatal(err)
				}
				want = "permission_denied"
			}
			o := Read(t.Context(), f)
			if o.Code != want {
				t.Fatalf("got %s want %s", o.Code, want)
			}
			if want != "ok" && len(o.Data) > 0 {
				t.Fatal("returned bytes on rejected read")
			}
			if want == "ok" && string(o.Data) != "approved" {
				t.Fatal("wrong data")
			}
		})
	}
}
func TestTraversalMountsAndIntermediateSymlinks(t *testing.T) {
	f := mapped(t)
	f.RelativePath = "../authorized_keys"
	if got := Read(t.Context(), f); got.Code != "unsafe_path" {
		t.Fatal(got)
	}
	f.RelativePath = "/etc/authorized_keys"
	if got := Read(t.Context(), f); got.Code != "unsafe_path" {
		t.Fatal(got)
	}
	f.RelativePath = "nested/authorized_keys"
	if err := os.Symlink(t.TempDir(), filepath.Join(f.BaseDir, "nested")); err != nil {
		t.Fatal(err)
	}
	if got := Read(t.Context(), f); got.Code != "unsafe_path" {
		t.Fatal(got)
	}
	f.BaseDir = "/"
	f.RelativePath = "proc/self/authorized_keys"
	if got := Read(t.Context(), f); got.Code != "unsafe_path" {
		t.Fatal("mount traversal was not rejected", got.Code)
	}
}
func TestRotationAndInPlaceChangesDiscardBytes(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			f := mapped(t)
			put(t, f, "approved")
			path := filepath.Join(f.BaseDir, f.RelativePath)
			o := readSnapshot(t.Context(), f, func() {
				if replace {
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
				}
				put(t, f, "changed and longer")
			})
			if o.Code != "changed_during_read" || len(o.Data) != 0 {
				t.Fatal("unstable snapshot accepted", o.Code)
			}
		})
	}
	f := mapped(t)
	put(t, f, "approved")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := Read(ctx, f); len(got.Data) > 0 {
		t.Fatal("cancelled read returned data")
	}
}
