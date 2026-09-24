//go:build !linux

package collector

import (
	"context"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func collect(ctx context.Context, c Config) (protocol.SystemInformation, protocol.SystemMeasurements, error) {
	i := protocol.SystemInformation{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	m := protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}}
	for _, p := range c.DiskPaths {
		m.Disks = append(m.Disks, protocol.DiskStats{Path: p})
	}
	for _, n := range c.NetworkInterfaces {
		m.Networks = append(m.Networks, protocol.NetworkStats{Interface: n})
	}
	return i, m, ctx.Err()
}
