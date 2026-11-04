//go:build linux

package collector

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"golang.org/x/sys/unix"
)

func readFixed(path string, limit int) string {
	b, err := localfile.Read(path, limit, false)
	if err != nil {
		return ""
	}
	return string(b)
}

// Linux cpu guest fields are already included in user/nice; do not count them
// twice. Treat idle and iowait as idle; counters that go backwards are unavailable.
func cpuTicks(s string) (total, idle uint64, err error) {
	line, _, _ := strings.Cut(s, "\n")
	f := strings.Fields(line)
	if len(f) < 9 || f[0] != "cpu" {
		return 0, 0, errors.New("missing CPU counters")
	}
	for i := 1; i <= 8; i++ {
		v, e := strconv.ParseUint(f[i], 10, 64)
		if e != nil || v > math.MaxUint64-total {
			return 0, 0, errors.New("invalid CPU counters")
		}
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return total, idle, nil
}
func memory(s string) protocol.MemoryStats {
	values := map[string]uint64{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || (f[0] != "MemTotal:" && f[0] != "MemAvailable:") {
			continue
		}
		if len(f) != 3 || f[2] != "kB" {
			return protocol.MemoryStats{}
		}
		if _, ok := values[f[0]]; ok {
			return protocol.MemoryStats{}
		}
		v, e := strconv.ParseUint(f[1], 10, 64)
		if e != nil || v > math.MaxUint64/1024 {
			return protocol.MemoryStats{}
		}
		values[f[0]] = v * 1024
	}
	total, tok := values["MemTotal:"]
	available, aok := values["MemAvailable:"]
	if !tok || !aok || total == 0 || available > total {
		return protocol.MemoryStats{}
	}
	return protocol.MemoryStats{Available: true, TotalBytes: total, AvailableBytes: available}
}
func network(s, name string) protocol.NetworkStats {
	n := protocol.NetworkStats{Interface: name}
	for _, line := range strings.Split(s, "\n") {
		iface, counters, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(iface) != name {
			continue
		}
		f := strings.Fields(counters)
		if len(f) != 16 {
			return n
		}
		rx, e1 := strconv.ParseUint(f[0], 10, 64)
		tx, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			return n
		}
		return protocol.NetworkStats{Interface: name, Available: true, RXBytes: rx, TXBytes: tx}
	}
	return n
}

func information(ctx context.Context) (protocol.SystemInformation, error) {
	i := protocol.SystemInformation{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	if err := ctx.Err(); err != nil {
		return i, err
	}
	stat := readFixed("/proc/stat", 256*1024)
	host, err := os.Hostname()
	kernel := strings.TrimSpace(readFixed("/proc/sys/kernel/osrelease", 4096))
	var boot int64
	for _, line := range strings.Split(stat, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "btime" {
			boot, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	if err == nil && host != "" && kernel != "" && protocol.CleanText(host, 255) && protocol.CleanText(kernel, 255) && boot > 0 && boot <= time.Now().Unix() {
		i.Available = true
		i.Hostname = host
		i.Kernel = kernel
		i.BootTime = boot
	}
	return i, ctx.Err()
}
func measurements(ctx context.Context, c Config) (protocol.SystemMeasurements, error) {
	m := protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}}
	if err := ctx.Err(); err != nil {
		return m, err
	}
	stat := readFixed("/proc/stat", 256*1024)
	total, idle, e1 := cpuTicks(stat)
	start := time.Now()
	timer := time.NewTimer(time.Duration(c.SampleMilliseconds) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return m, ctx.Err()
	case <-timer.C:
	}
	next, nextIdle, e2 := cpuTicks(readFixed("/proc/stat", 256*1024))
	window := time.Since(start).Milliseconds()
	if e1 == nil && e2 == nil && next > total && nextIdle >= idle && nextIdle-idle <= next-total && window >= 100 && window <= 10000 {
		m.CPU = protocol.CPUStats{Available: true, BusyPercent: 100 * float64((next-total)-(nextIdle-idle)) / float64(next-total), WindowMS: window}
	}
	m.Memory = memory(readFixed("/proc/meminfo", 64*1024))
	for _, p := range c.DiskPaths {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		d := protocol.DiskStats{Path: p}
		var fs unix.Statfs_t
		if unix.Statfs(p, &fs) == nil && fs.Bsize > 0 && fs.Blocks <= math.MaxUint64/uint64(fs.Bsize) && fs.Bavail <= fs.Blocks {
			d.Available = true
			d.TotalBytes = fs.Blocks * uint64(fs.Bsize)
			d.AvailableBytes = fs.Bavail * uint64(fs.Bsize)
		}
		m.Disks = append(m.Disks, d)
	}
	dev := readFixed("/proc/net/dev", 128*1024)
	for _, name := range c.NetworkInterfaces {
		m.Networks = append(m.Networks, network(dev, name))
	}
	return m, ctx.Err()
}
