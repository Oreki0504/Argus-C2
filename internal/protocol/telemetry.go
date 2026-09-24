package protocol

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxHeartbeatBytes = 16 * 1024
const TaskHeartbeatVersion = 2

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
type Heartbeat struct {
	Version         int                `json:"version"`
	AgentID         string             `json:"agent_id"`
	EnrollmentEpoch string             `json:"enrollment_epoch"`
	SentAt          int64              `json:"sent_at"`
	Info            SystemInformation  `json:"system_info"`
	Metrics         SystemMeasurements `json:"system_metrics"`
	PolicyDigest    string             `json:"policy_digest,omitempty"`
	TaskState       string             `json:"task_state,omitempty"`
}

func CleanText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	return strings.IndexFunc(s, unicode.IsControl) == -1
}
func (h Heartbeat) Validate() error {
	bad := errors.New("invalid heartbeat")
	if (h.Version != Version && h.Version != TaskHeartbeatVersion) || h.SentAt <= 0 || (identity.Node{AgentID: h.AgentID, EnrollmentEpoch: h.EnrollmentEpoch}).Validate() != nil {
		return bad
	}
	if h.Version == Version && (h.PolicyDigest != "" || h.TaskState != "") {
		return bad
	}
	if h.Version == TaskHeartbeatVersion && (!identity.Hex(h.PolicyDigest, 64) || (h.TaskState != "ready" && h.TaskState != "paused" && h.TaskState != "blocked")) {
		return bad
	}
	if err := h.Info.Validate(h.SentAt); err != nil {
		return err
	}
	return h.Metrics.Validate()
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

func DecodeHeartbeat(data []byte) (Heartbeat, error) {
	var raw struct {
		Version         int             `json:"version"`
		AgentID         string          `json:"agent_id"`
		EnrollmentEpoch string          `json:"enrollment_epoch"`
		SentAt          int64           `json:"sent_at"`
		Info            json.RawMessage `json:"system_info"`
		Metrics         json.RawMessage `json:"system_metrics"`
		PolicyDigest    string          `json:"policy_digest"`
		TaskState       string          `json:"task_state"`
	}
	if len(data) > MaxHeartbeatBytes {
		return Heartbeat{}, errors.New("heartbeat exceeds size limit")
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return Heartbeat{}, err
	}
	fields := []string{"version", "agent_id", "enrollment_epoch", "sent_at", "system_info", "system_metrics"}
	if header.Version == TaskHeartbeatVersion {
		fields = append(fields, "policy_digest", "task_state")
	}
	if err := strictjson.Decode(data, &raw, MaxHeartbeatBytes, fields...); err != nil {
		return Heartbeat{}, err
	}
	h := Heartbeat{Version: raw.Version, AgentID: raw.AgentID, EnrollmentEpoch: raw.EnrollmentEpoch, SentAt: raw.SentAt, PolicyDigest: raw.PolicyDigest, TaskState: raw.TaskState}
	var err error
	h.Info, err = DecodeInformation(raw.Info)
	if err != nil {
		return Heartbeat{}, err
	}
	h.Metrics, err = DecodeMeasurements(raw.Metrics)
	if err != nil {
		return Heartbeat{}, err
	}
	return h, h.Validate()
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
