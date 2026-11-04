package protocol

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxHeartbeatBytes = 16 * 1024

// Unavailable measurements carry zero values and Available=false, never a
// fabricated successful measurement. Network counters are cumulative bytes.
type SystemInformation struct {
	Available    bool   `json:"available"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	Kernel       string `json:"kernel"`
	BootTime     int64  `json:"boot_time"`
}
type CPUStats struct {
	Available   bool    `json:"available"`
	BusyPercent float64 `json:"busy_percent"`
	WindowMS    int64   `json:"window_ms"`
}
type MemoryStats struct {
	Available      bool   `json:"available"`
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}
type DiskStats struct {
	Path           string `json:"path"`
	Available      bool   `json:"available"`
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}
type NetworkStats struct {
	Interface string `json:"interface"`
	Available bool   `json:"available"`
	RXBytes   uint64 `json:"rx_bytes"`
	TXBytes   uint64 `json:"tx_bytes"`
}
type SystemMeasurements struct {
	CPU      CPUStats       `json:"cpu"`
	Memory   MemoryStats    `json:"memory"`
	Disks    []DiskStats    `json:"disks"`
	Networks []NetworkStats `json:"networks"`
}

func CleanText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	return strings.IndexFunc(s, unicode.IsControl) == -1
}
func (i SystemInformation) Validate(now int64) error {
	bad := errors.New("invalid system information")
	if !CleanText(i.OS, 32) || i.OS == "" || !CleanText(i.Architecture, 32) || i.Architecture == "" || !CleanText(i.Hostname, 255) || !CleanText(i.Kernel, 255) || i.BootTime < 0 || i.BootTime > now {
		return bad
	}
	if i.Available && (i.Hostname == "" || i.Kernel == "" || i.BootTime == 0) {
		return bad
	}
	if !i.Available && (i.Hostname != "" || i.Kernel != "" || i.BootTime != 0) {
		return bad
	}
	return nil
}
func (m SystemMeasurements) Validate() error {
	bad := errors.New("invalid system measurements")
	if math.IsNaN(m.CPU.BusyPercent) || math.IsInf(m.CPU.BusyPercent, 0) || m.CPU.BusyPercent < 0 || m.CPU.BusyPercent > 100 {
		return bad
	}
	if m.CPU.Available {
		if m.CPU.WindowMS < 100 || m.CPU.WindowMS > 10000 {
			return bad
		}
	} else if m.CPU.BusyPercent != 0 || m.CPU.WindowMS != 0 {
		return bad
	}
	if m.Memory.AvailableBytes > m.Memory.TotalBytes || (m.Memory.Available && m.Memory.TotalBytes == 0) || (!m.Memory.Available && (m.Memory.TotalBytes != 0 || m.Memory.AvailableBytes != 0)) {
		return bad
	}
	if m.Disks == nil || m.Networks == nil || len(m.Disks) > 8 || len(m.Networks) > 16 {
		return bad
	}
	seen := map[string]bool{}
	for _, d := range m.Disks {
		if !CleanText(d.Path, 256) || !strings.HasPrefix(d.Path, "/") || seen[d.Path] || d.AvailableBytes > d.TotalBytes || (!d.Available && (d.TotalBytes != 0 || d.AvailableBytes != 0)) {
			return bad
		}
		seen[d.Path] = true
	}
	seen = map[string]bool{}
	for _, n := range m.Networks {
		if !CleanText(n.Interface, 15) || n.Interface == "" || strings.ContainsAny(n.Interface, "/: ") || seen[n.Interface] || (!n.Available && (n.RXBytes != 0 || n.TXBytes != 0)) {
			return bad
		}
		seen[n.Interface] = true
	}
	return nil
}

func DecodeInformation(data []byte) (SystemInformation, error) {
	var i SystemInformation
	if err := strictjson.Decode(data, &i, 2048, "available", "os", "architecture", "hostname", "kernel", "boot_time"); err != nil {
		return i, err
	}
	return i, nil
}
func DecodeMeasurements(data []byte) (SystemMeasurements, error) {
	var metrics SystemMeasurements
	var m struct {
		CPU      json.RawMessage   `json:"cpu"`
		Memory   json.RawMessage   `json:"memory"`
		Disks    []json.RawMessage `json:"disks"`
		Networks []json.RawMessage `json:"networks"`
	}
	if err := strictjson.Decode(data, &m, MaxHeartbeatBytes, "cpu", "memory", "disks", "networks"); err != nil {
		return SystemMeasurements{}, err
	}
	if len(m.Disks) > 8 || len(m.Networks) > 16 {
		return SystemMeasurements{}, errors.New("too many telemetry resources")
	}
	if err := strictjson.Decode(m.CPU, &metrics.CPU, 256, "available", "busy_percent", "window_ms"); err != nil {
		return SystemMeasurements{}, err
	}
	if err := strictjson.Decode(m.Memory, &metrics.Memory, 256, "available", "total_bytes", "available_bytes"); err != nil {
		return SystemMeasurements{}, err
	}
	metrics.Disks = []DiskStats{}
	metrics.Networks = []NetworkStats{}
	for _, v := range m.Disks {
		var d DiskStats
		if err := strictjson.Decode(v, &d, 2048, "path", "available", "total_bytes", "available_bytes"); err != nil {
			return SystemMeasurements{}, err
		}
		metrics.Disks = append(metrics.Disks, d)
	}
	for _, v := range m.Networks {
		var n NetworkStats
		if err := strictjson.Decode(v, &n, 256, "interface", "available", "rx_bytes", "tx_bytes"); err != nil {
			return SystemMeasurements{}, err
		}
		metrics.Networks = append(metrics.Networks, n)
	}
	return metrics, metrics.Validate()
}
