package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestParseOSRelease(t *testing.T) {
	for _, tt := range []struct {
		name, raw, want string
	}{
		{"debian", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nID=debian\n", "Debian 13"},
		{"ubuntu", "ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian\n", "Ubuntu 24.04"},
		{"alpine", "ID=alpine\nVERSION_ID=3.22.1\n", "Alpine 3.22.1"},
		{"rhel", "NAME=\"Red Hat Enterprise Linux\"\nID=rhel\nVERSION_ID=\"9.6\"", "Red Hat 9.6"},
		{"suse", "ID=opensuse-leap\nVERSION_ID=\"15.6\"", "openSUSE 15.6"},
		{"amazon", "ID=amzn\nVERSION_ID=\"2023\"", "Amazon Linux 2023"},
		{"rolling", "ID=arch\nPRETTY_NAME=\"Arch Linux\"", "Arch"},
		{"quoted", "# Comment\n\n ID='debian' \nVERSION_ID='13'\n", "Debian 13"},
		{"duplicate uses last", "ID=ubuntu\nID=debian\nVERSION_ID=12\nVERSION_ID=13", "Debian 13"},
		{"unknown derivative", "ID=custom\nID_LIKE=debian\nVERSION_ID=13", "linux"},
		{"empty", "", "linux"},
		{"invalid", "not an os-release file", "linux"},
		{"mismatched quote", "ID=\"debian'\nVERSION_ID=13", "linux"},
		{"shell expansion", "ID=debian\nVERSION_ID=\"$(uname -r)\"", "Debian"},
		{"control character", "ID=debian\nVERSION_ID=\"13\x00\"", "Debian"},
		{"oversized version", "ID=debian\nVERSION_ID=" + strings.Repeat("1", 100), "Debian"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOSRelease(tt.raw)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			info := protocol.SystemInformation{OS: got, Architecture: "amd64"}
			if err := info.Validate(1); err != nil {
				t.Fatal("distribution violates the wire contract", err)
			}
		})
	}
}

func TestLinuxDistributionFiles(t *testing.T) {
	dir := t.TempDir()
	etc, vendor := filepath.Join(dir, "etc-os-release"), filepath.Join(dir, "vendor-os-release")
	write := func(path, raw string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want string) {
		t.Helper()
		if got := linuxDistribution(etc, vendor); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	check("linux")
	write(vendor, "ID=ubuntu\nVERSION_ID=24.04\n")
	check("Ubuntu 24.04")
	write(etc, "ID=debian\nVERSION_ID=13\n")
	check("Debian 13")
	// Do not merge VERSION_ID from a different vendor release file.
	write(etc, "ID=arch\n")
	check("Arch")
	write(etc, strings.Repeat("#", 16*1024+1))
	check("Ubuntu 24.04")
	if err := os.Remove(etc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(vendor), etc); err != nil {
		t.Fatal(err)
	}
	check("Ubuntu 24.04")
}
