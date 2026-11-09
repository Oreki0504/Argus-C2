package console

import (
	"encoding/json"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestProjectSystemDistributionAndArchitecture(t *testing.T) {
	for _, tt := range []struct {
		os, arch, want string
	}{
		{"Debian 13", "amd64", "Debian 13"},
		{"Ubuntu 24.04", "arm64", "Ubuntu 24.04"},
		{"Alpine 3.22.1", "amd64", "Alpine 3.22.1"},
		{"Red Hat 9.6", "amd64", "Red Hat 9.6"},
		{"Arch", "arm64", "Arch"},
		{"linux", "amd64", "linux"},
		{"Debian 13 private-host", "amd64", "Debian 13"},
	} {
		t.Run(tt.os, func(t *testing.T) {
			info := protocol.SystemInformation{
				Available: true, OS: tt.os, Architecture: tt.arch,
				Hostname: "private-host", Kernel: "6.12.0-private", BootTime: 100,
			}
			raw, err := json.Marshal(info)
			if err != nil {
				t.Fatal(err)
			}
			got := projectSystem(string(raw), 200)
			if got.OS == nil || *got.OS != tt.want || got.Architecture == nil || *got.Architecture != tt.arch {
				t.Fatalf("distribution or architecture lost in public projection: %+v", got)
			}
		})
	}
}
