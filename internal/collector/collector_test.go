package collector

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
)

func TestLocalScopeAndCancellation(t *testing.T) {
	c := Config{IntervalSeconds: 30, SampleMilliseconds: 100, DiskPaths: []string{"/"}, NetworkInterfaces: []string{"lo"}}
	h, err := Collect(context.Background(), identity.New(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Metrics.Disks) != 1 || h.Metrics.Disks[0].Path != "/" || len(h.Metrics.Networks) != 1 || h.Metrics.Networks[0].Interface != "lo" {
		t.Fatal("collector expanded local scope")
	}
	if runtime.GOOS == "linux" {
		if !h.Info.Available || !h.Metrics.CPU.Available || !h.Metrics.Memory.Available || !h.Metrics.Disks[0].Available || !h.Metrics.Networks[0].Available {
			t.Fatalf("Linux collectors failed: %+v", h)
		}
	} else if h.Info.Available || h.Metrics.CPU.Available || h.Metrics.Memory.Available || h.Metrics.Disks[0].Available || h.Metrics.Networks[0].Available {
		t.Fatal("unsupported platform fabricated measurements")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := Collect(ctx, identity.New(), c); err == nil {
		t.Fatal("cancellation ignored")
	}
	if time.Since(start) > time.Second {
		t.Fatal("canceled collection was too slow")
	}
	for _, bad := range []Config{
		{IntervalSeconds: 1, SampleMilliseconds: 100, DiskPaths: []string{}, NetworkInterfaces: []string{}},
		{IntervalSeconds: 30, SampleMilliseconds: 100, DiskPaths: []string{"/../etc"}, NetworkInterfaces: []string{}},
		{IntervalSeconds: 30, SampleMilliseconds: 100, DiskPaths: []string{}, NetworkInterfaces: []string{"lo", "lo"}},
		{IntervalSeconds: 30, SampleMilliseconds: 100, DiskPaths: []string{}, NetworkInterfaces: []string{"eth0\n"}},
	} {
		if bad.Validate() == nil {
			t.Fatal("invalid local configuration accepted")
		}
	}
}
