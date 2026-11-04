//go:build linux

package service

import (
	"os"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func TestLiveSystemdReadOnly(t *testing.T) {
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/argus-test-socket")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/argus-test-socket")
	r, err := Collect(t.Context(), resources.Service{ID: "journal", Unit: "systemd-journald.service"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Available {
		if os.Getenv("ARGUS_REQUIRE_SYSTEMD") == "1" {
			t.Fatalf("required native systemd query unavailable: %s", r.Code)
		}
		t.Skipf("live systemd not available: %s", r.Code)
	}
	if r.Unit != "systemd-journald.service" || r.LoadState != "loaded" {
		t.Fatal(r)
	}
	r, err = Collect(t.Context(), resources.Service{ID: "absent", Unit: "argus-nonexistent-test-unit.service"})
	if err != nil || r.Available || r.Code != "unit_not_loaded" {
		t.Fatal("unknown unit was loaded or misreported", r, err)
	}
}
