package collector

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestLocalScopeAndCancellation(t *testing.T) {
	c := Config{SampleMilliseconds: 100, DiskPaths: []string{"/"}, NetworkInterfaces: []string{"lo"}}
	metrics, err := Measurements(context.Background(), c)
	info, infoErr := Information(context.Background())
	if infoErr != nil {
		t.Fatal(infoErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics.Disks) != 1 || metrics.Disks[0].Path != "/" || len(metrics.Networks) != 1 || metrics.Networks[0].Interface != "lo" {
		t.Fatal("collector expanded local scope")
	}
	if runtime.GOOS == "linux" {
		if !info.Available || !metrics.CPU.Available || !metrics.Memory.Available || !metrics.Disks[0].Available || !metrics.Networks[0].Available {
			t.Fatalf("Linux collectors failed: %+v", metrics)
		}
	} else if info.Available || metrics.CPU.Available || metrics.Memory.Available || metrics.Disks[0].Available || metrics.Networks[0].Available {
		t.Fatal("unsupported platform fabricated measurements")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := Measurements(ctx, c); err == nil {
		t.Fatal("cancellation ignored")
	}
	if time.Since(start) > time.Second {
		t.Fatal("canceled collection was too slow")
	}
	for _, bad := range []Config{
		{SampleMilliseconds: 1, DiskPaths: []string{}, NetworkInterfaces: []string{}},
		{SampleMilliseconds: 100, DiskPaths: []string{"/../etc"}, NetworkInterfaces: []string{}},
		{SampleMilliseconds: 100, DiskPaths: []string{}, NetworkInterfaces: []string{"lo", "lo"}},
		{SampleMilliseconds: 100, DiskPaths: []string{}, NetworkInterfaces: []string{"eth0\n"}},
	} {
		if bad.Validate() == nil {
			t.Fatal("invalid local configuration accepted")
		}
	}
}
