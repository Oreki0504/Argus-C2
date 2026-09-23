package localfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 6, true); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 5, true); err == nil {
		t.Fatal("accepted oversized file")
	}
	if _, err := Read(dir, 4096, false); err == nil {
		t.Fatal("accepted directory")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path, 6, true); err == nil {
			t.Fatal("accepted broadly readable key")
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(link, 6, false); err == nil {
			t.Fatal("accepted symlink configuration")
		}
	}
}
