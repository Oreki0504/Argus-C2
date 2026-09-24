// Package collector implements fixed, read-only system.info and system.metrics
// collectors. It has no subprocess, task dispatch, or remote configuration API.
package collector

import (
	"context"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Config struct {
	IntervalSeconds    int      `json:"interval_seconds"`
	SampleMilliseconds int      `json:"sample_milliseconds"`
	DiskPaths          []string `json:"disk_paths"`
	NetworkInterfaces  []string `json:"network_interfaces"`
}

func (c Config) Validate() error {
	if c.IntervalSeconds < 10 || c.IntervalSeconds > 300 || c.SampleMilliseconds < 100 || c.SampleMilliseconds > 5000 || c.DiskPaths == nil || c.NetworkInterfaces == nil || len(c.DiskPaths) > 8 || len(c.NetworkInterfaces) > 16 {
		return errors.New("invalid local telemetry limits")
	}
	seen := map[string]bool{}
	for _, p := range c.DiskPaths {
		if !protocol.CleanText(p, 256) || !strings.HasPrefix(p, "/") || path.Clean(p) != p || seen[p] {
			return errors.New("disk paths must be unique canonical absolute Linux paths")
		}
		seen[p] = true
	}
	seen = map[string]bool{}
	for _, n := range c.NetworkInterfaces {
		if !protocol.CleanText(n, 15) || n == "" || strings.ContainsAny(n, "/: ") || seen[n] {
			return errors.New("invalid or duplicate network interface")
		}
		seen[n] = true
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	b, err := localfile.Read(path, 4096, false)
	if err != nil {
		return Config{}, err
	}
	return DecodeConfig(b)
}
func DecodeConfig(b []byte) (Config, error) {
	var c Config
	if err := strictjson.Decode(b, &c, 4096, "interval_seconds", "sample_milliseconds", "disk_paths", "network_interfaces"); err != nil {
		return Config{}, err
	}
	return c, c.Validate()
}
func Collect(ctx context.Context, n identity.Node, c Config) (protocol.Heartbeat, error) {
	if err := n.Validate(); err != nil {
		return protocol.Heartbeat{}, err
	}
	if err := c.Validate(); err != nil {
		return protocol.Heartbeat{}, err
	}
	info, err := Information(ctx)
	if err != nil {
		return protocol.Heartbeat{}, err
	}
	metrics, err := Measurements(ctx, c)
	if err != nil {
		return protocol.Heartbeat{}, err
	}
	h := protocol.Heartbeat{Version: protocol.Version, AgentID: n.AgentID, EnrollmentEpoch: n.EnrollmentEpoch, SentAt: time.Now().Unix(), Info: info, Metrics: metrics}
	return h, h.Validate()
}

func Information(ctx context.Context) (protocol.SystemInformation, error) { return information(ctx) }
func Measurements(ctx context.Context, c Config) (protocol.SystemMeasurements, error) {
	if err := c.Validate(); err != nil {
		return protocol.SystemMeasurements{}, err
	}
	return measurements(ctx, c)
}
