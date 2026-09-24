// Package policy defines immutable snapshots of locally administered authority.
package policy

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/collector"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Policy struct {
	Version            int              `json:"version"`
	Paused             bool             `json:"paused"`
	AllowSystemInfo    bool             `json:"allow_system_info"`
	AllowSystemMetrics bool             `json:"allow_system_metrics"`
	PollSeconds        int              `json:"poll_seconds"`
	TimeoutSeconds     int              `json:"timeout_seconds"`
	MaxPerMinute       int              `json:"max_per_minute"`
	Burst              int              `json:"burst"`
	MaxResultBytes     int              `json:"max_result_bytes"`
	PendingBytes       int              `json:"pending_bytes"`
	Telemetry          collector.Config `json:"telemetry"`
}

func (p Policy) Validate() error {
	if p.Version != 1 || p.PollSeconds < 5 || p.PollSeconds > 60 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 30 || p.MaxPerMinute < 1 || p.MaxPerMinute > 30 || p.Burst < 1 || p.Burst > 5 || p.Burst > p.MaxPerMinute || p.MaxResultBytes < 1024 || p.MaxResultBytes > 16384 || p.PendingBytes < p.MaxResultBytes || p.PendingBytes > 32*1024*1024 {
		return errors.New("invalid local task limits")
	}
	return p.Telemetry.Validate()
}
func Decode(data []byte) (Policy, error) {
	var raw struct {
		Version            int             `json:"version"`
		Paused             bool            `json:"paused"`
		AllowSystemInfo    bool            `json:"allow_system_info"`
		AllowSystemMetrics bool            `json:"allow_system_metrics"`
		PollSeconds        int             `json:"poll_seconds"`
		TimeoutSeconds     int             `json:"timeout_seconds"`
		MaxPerMinute       int             `json:"max_per_minute"`
		Burst              int             `json:"burst"`
		MaxResultBytes     int             `json:"max_result_bytes"`
		PendingBytes       int             `json:"pending_bytes"`
		Telemetry          json.RawMessage `json:"telemetry"`
	}
	if err := strictjson.Decode(data, &raw, 8192, "version", "paused", "allow_system_info", "allow_system_metrics", "poll_seconds", "timeout_seconds", "max_per_minute", "burst", "max_result_bytes", "pending_bytes", "telemetry"); err != nil {
		return Policy{}, err
	}
	c, err := collector.DecodeConfig(raw.Telemetry)
	if err != nil {
		return Policy{}, err
	}
	p := Policy{raw.Version, raw.Paused, raw.AllowSystemInfo, raw.AllowSystemMetrics, raw.PollSeconds, raw.TimeoutSeconds, raw.MaxPerMinute, raw.Burst, raw.MaxResultBytes, raw.PendingBytes, c}
	return p, p.Validate()
}
func Load(path string) (Policy, error) {
	data, err := localfile.Read(path, 8192, false)
	if err != nil {
		return Policy{}, err
	}
	return Decode(data)
}
func (p Policy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	p.Telemetry.DiskPaths = append([]string{}, p.Telemetry.DiskPaths...)
	sort.Strings(p.Telemetry.DiskPaths)
	p.Telemetry.NetworkInterfaces = append([]string{}, p.Telemetry.NetworkInterfaces...)
	sort.Strings(p.Telemetry.NetworkInterfaces)
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return audit.Digest(append([]byte("argus-c2/policy/v1\x00"), data...)), nil
}
func (p Policy) Allows(kind protocol.TaskType) bool {
	return !p.Paused && (kind == protocol.SystemInfo && p.AllowSystemInfo || kind == protocol.SystemMetrics && p.AllowSystemMetrics)
}
