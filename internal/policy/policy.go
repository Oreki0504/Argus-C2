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
	"github.com/Oreki0504/Argus-C2/internal/resources"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Policy struct {
	Version            int                    `json:"version"`
	Paused             bool                   `json:"paused"`
	AllowSystemInfo    bool                   `json:"allow_system_info"`
	AllowSystemMetrics bool                   `json:"allow_system_metrics"`
	PollSeconds        int                    `json:"poll_seconds"`
	TimeoutSeconds     int                    `json:"timeout_seconds"`
	MaxPerMinute       int                    `json:"max_per_minute"`
	Burst              int                    `json:"burst"`
	MaxResultBytes     int                    `json:"max_result_bytes"`
	PendingBytes       int                    `json:"pending_bytes"`
	Telemetry          collector.Config       `json:"telemetry"`
	AllowSSHAudit      bool                   `json:"allow_ssh_audit,omitempty"`
	AllowServiceStatus bool                   `json:"allow_service_status,omitempty"`
	SSHProfiles        []resources.SSHProfile `json:"ssh_profiles,omitempty"`
	Services           []resources.Service    `json:"services,omitempty"`
}

// Keep v1's serialized bytes stable; v2 always emits its explicit opt-in fields.
func (p Policy) MarshalJSON() ([]byte, error) {
	type wire Policy
	if p.Version != 2 {
		return json.Marshal(wire(p))
	}
	return json.Marshal(struct {
		wire
		AllowSSHAudit      bool                   `json:"allow_ssh_audit"`
		AllowServiceStatus bool                   `json:"allow_service_status"`
		SSHProfiles        []resources.SSHProfile `json:"ssh_profiles"`
		Services           []resources.Service    `json:"services"`
	}{wire(p), p.AllowSSHAudit, p.AllowServiceStatus, p.SSHProfiles, p.Services})
}

func (p Policy) Validate() error {
	if (p.Version != 1 && p.Version != 2) || p.PollSeconds < 5 || p.PollSeconds > 60 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 30 || p.MaxPerMinute < 1 || p.MaxPerMinute > 30 || p.Burst < 1 || p.Burst > 5 || p.Burst > p.MaxPerMinute || p.MaxResultBytes < 1024 || p.MaxResultBytes > 16384 || p.PendingBytes < p.MaxResultBytes || p.PendingBytes > 32*1024*1024 {
		return errors.New("invalid local task limits")
	}
	if p.Version == 1 && (p.AllowSSHAudit || p.AllowServiceStatus || p.SSHProfiles != nil || p.Services != nil) {
		return errors.New("version 1 policy cannot enable new resources")
	}
	if p.Version == 2 {
		if p.SSHProfiles == nil || p.Services == nil || len(p.SSHProfiles) > resources.MaxProfiles || len(p.Services) > resources.MaxServices {
			return errors.New("invalid resource counts")
		}
		seen := map[string]bool{}
		for _, profile := range p.SSHProfiles {
			if err := profile.Validate(); err != nil {
				return err
			}
			if seen[profile.ID] {
				return errors.New("duplicate SSH profile")
			}
			seen[profile.ID] = true
		}
		seen = map[string]bool{}
		for _, service := range p.Services {
			if err := service.Validate(); err != nil {
				return err
			}
			if seen[service.ID] {
				return errors.New("duplicate service ID")
			}
			seen[service.ID] = true
		}
	}
	return p.Telemetry.Validate()
}
func Decode(data []byte) (Policy, error) {
	var raw struct {
		Version            int               `json:"version"`
		Paused             bool              `json:"paused"`
		AllowSystemInfo    bool              `json:"allow_system_info"`
		AllowSystemMetrics bool              `json:"allow_system_metrics"`
		PollSeconds        int               `json:"poll_seconds"`
		TimeoutSeconds     int               `json:"timeout_seconds"`
		MaxPerMinute       int               `json:"max_per_minute"`
		Burst              int               `json:"burst"`
		MaxResultBytes     int               `json:"max_result_bytes"`
		PendingBytes       int               `json:"pending_bytes"`
		Telemetry          json.RawMessage   `json:"telemetry"`
		AllowSSHAudit      bool              `json:"allow_ssh_audit"`
		AllowServiceStatus bool              `json:"allow_service_status"`
		SSHProfiles        []json.RawMessage `json:"ssh_profiles"`
		Services           []json.RawMessage `json:"services"`
	}
	if len(data) > 32768 {
		return Policy{}, errors.New("policy too large")
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return Policy{}, err
	}
	fields := []string{"version", "paused", "allow_system_info", "allow_system_metrics", "poll_seconds", "timeout_seconds", "max_per_minute", "burst", "max_result_bytes", "pending_bytes", "telemetry"}
	if header.Version == 2 {
		fields = append(fields, "allow_ssh_audit", "allow_service_status", "ssh_profiles", "services")
	}
	if err := strictjson.Decode(data, &raw, 32768, fields...); err != nil {
		return Policy{}, err
	}
	c, err := collector.DecodeConfig(raw.Telemetry)
	if err != nil {
		return Policy{}, err
	}
	p := Policy{Version: raw.Version, Paused: raw.Paused, AllowSystemInfo: raw.AllowSystemInfo, AllowSystemMetrics: raw.AllowSystemMetrics, PollSeconds: raw.PollSeconds, TimeoutSeconds: raw.TimeoutSeconds, MaxPerMinute: raw.MaxPerMinute, Burst: raw.Burst, MaxResultBytes: raw.MaxResultBytes, PendingBytes: raw.PendingBytes, Telemetry: c, AllowSSHAudit: raw.AllowSSHAudit, AllowServiceStatus: raw.AllowServiceStatus}
	if p.Version == 2 {
		if len(raw.SSHProfiles) > resources.MaxProfiles || len(raw.Services) > resources.MaxServices {
			return Policy{}, errors.New("too many local resources")
		}
		p.SSHProfiles = []resources.SSHProfile{}
		p.Services = []resources.Service{}
		for _, b := range raw.SSHProfiles {
			v, err := resources.DecodeProfile(b)
			if err != nil {
				return Policy{}, err
			}
			p.SSHProfiles = append(p.SSHProfiles, v)
		}
		for _, b := range raw.Services {
			v, err := resources.DecodeService(b)
			if err != nil {
				return Policy{}, err
			}
			p.Services = append(p.Services, v)
		}
	}
	return p, p.Validate()
}
func Load(path string) (Policy, error) {
	data, err := localfile.Read(path, 32768, false)
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
	if p.Version == 2 {
		p.Services = append([]resources.Service{}, p.Services...)
		sort.Slice(p.Services, func(i, j int) bool { return p.Services[i].ID < p.Services[j].ID })
		p.SSHProfiles = append([]resources.SSHProfile{}, p.SSHProfiles...)
		sort.Slice(p.SSHProfiles, func(i, j int) bool { return p.SSHProfiles[i].ID < p.SSHProfiles[j].ID })
		for i := range p.SSHProfiles {
			p.SSHProfiles[i].Files = append([]resources.SSHFile{}, p.SSHProfiles[i].Files...)
			sort.Slice(p.SSHProfiles[i].Files, func(a, b int) bool { return p.SSHProfiles[i].Files[a].ID < p.SSHProfiles[i].Files[b].ID })
		}
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	domain := "argus-c2/policy/v1\x00"
	if p.Version == 2 {
		domain = "argus-c2/policy/v2\x00"
	}
	return audit.Digest(append([]byte(domain), data...)), nil
}
func (p Policy) Allows(kind protocol.TaskType) bool {
	return !p.Paused && (kind == protocol.SystemInfo && p.AllowSystemInfo || kind == protocol.SystemMetrics && p.AllowSystemMetrics || kind == protocol.SSHAudit && p.Version == 2 && p.AllowSSHAudit || kind == protocol.ServiceStatus && p.Version == 2 && p.AllowServiceStatus)
}

func (p Policy) SSHProfile(id string) (resources.SSHProfile, bool) {
	for _, v := range p.SSHProfiles {
		if v.ID == id {
			return v, true
		}
	}
	return resources.SSHProfile{}, false
}
func (p Policy) Service(id string) (resources.Service, bool) {
	for _, v := range p.Services {
		if v.ID == id {
			return v, true
		}
	}
	return resources.Service{}, false
}
func (p Policy) AllowsResource(t protocol.Task) bool {
	if t.Type == protocol.SSHAudit {
		id, err := t.Resource()
		_, ok := p.SSHProfile(id)
		return err == nil && ok
	}
	if t.Type == protocol.ServiceStatus {
		id, err := t.Resource()
		_, ok := p.Service(id)
		return err == nil && ok
	}
	return t.Type == protocol.SystemInfo || t.Type == protocol.SystemMetrics
}
