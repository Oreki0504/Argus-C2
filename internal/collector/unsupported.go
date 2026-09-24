//go:build !linux

package collector

import (
	"context"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func information(ctx context.Context) (protocol.SystemInformation, error) {
	i := protocol.SystemInformation{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	return i, ctx.Err()
}
func measurements(ctx context.Context, c Config) (protocol.SystemMeasurements, error) {
	m := protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}}
	for _, p := range c.DiskPaths {
		m.Disks = append(m.Disks, protocol.DiskStats{Path: p})
	}
	for _, n := range c.NetworkInterfaces {
		m.Networks = append(m.Networks, protocol.NetworkStats{Interface: n})
	}
	return m, ctx.Err()
}
