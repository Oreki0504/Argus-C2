// Package policy is local authority; no server request can change these limits.
package policy

import (
	"encoding/json"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/collectors/system"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Policy struct {
	Allowed        []protocol.TaskType    `json:"allowed"`
	PollSeconds    int                    `json:"poll_seconds"`
	TimeoutSeconds int                    `json:"timeout_seconds"`
	MaxResultBytes int                    `json:"max_result_bytes"`
	Telemetry      collector.Config       `json:"telemetry"`
	Services       []resources.Service    `json:"services"`
	SSHProfiles    []resources.SSHProfile `json:"ssh_profiles"`
}

func Default() Policy {
	return Policy{Allowed: []protocol.TaskType{protocol.SystemInfo, protocol.SystemMetrics}, PollSeconds: 10, TimeoutSeconds: 10, MaxResultBytes: 65536, Telemetry: collector.Config{SampleMilliseconds: 1000, DiskPaths: []string{"/"}, NetworkInterfaces: []string{}}, Services: []resources.Service{}, SSHProfiles: []resources.SSHProfile{}}
}
func (p Policy) Validate() error {
	if p.Allowed == nil || len(p.Allowed) > 6 || p.PollSeconds < 5 || p.PollSeconds > 60 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 30 || p.MaxResultBytes < 1024 || p.MaxResultBytes > protocol.MaxResultBytes || p.Services == nil || p.SSHProfiles == nil || len(p.Services) > 16 || len(p.SSHProfiles) > 4 {
		return errors.New("invalid local policy limits")
	}
	seen := map[protocol.TaskType]bool{}
	for _, t := range p.Allowed {
		if !protocol.KnownTask(t) || seen[t] {
			return errors.New("unknown or duplicate collector")
		}
		seen[t] = true
	}
	ids := map[string]bool{}
	for _, s := range p.Services {
		if e := s.Validate(); e != nil {
			return e
		}
		if ids[s.ID] {
			return errors.New("duplicate service")
		}
		ids[s.ID] = true
	}
	ids = map[string]bool{}
	for _, s := range p.SSHProfiles {
		if e := s.Validate(); e != nil {
			return e
		}
		if ids[s.ID] {
			return errors.New("duplicate SSH profile")
		}
		ids[s.ID] = true
	}
	return p.Telemetry.Validate()
}
func Decode(b []byte) (Policy, error) {
	var p Policy
	if e := strictjson.Decode(b, &p, 32768, "allowed", "poll_seconds", "timeout_seconds", "max_result_bytes", "telemetry", "services", "ssh_profiles"); e != nil {
		return p, e
	}
	var nested struct {
		Telemetry json.RawMessage   `json:"telemetry"`
		Services  []json.RawMessage `json:"services"`
		Profiles  []json.RawMessage `json:"ssh_profiles"`
	}
	if err := json.Unmarshal(b, &nested); err != nil {
		return p, err
	}
	if _, err := collector.DecodeConfig(nested.Telemetry); err != nil {
		return p, err
	}
	for _, v := range nested.Services {
		if _, err := resources.DecodeService(v); err != nil {
			return p, err
		}
	}
	for _, v := range nested.Profiles {
		if _, err := resources.DecodeProfile(v); err != nil {
			return p, err
		}
	}
	return p, p.Validate()
}
func Load(path string) (Policy, error) {
	b, e := localfile.Read(path, 32768, false)
	if e != nil {
		return Policy{}, e
	}
	return Decode(b)
}
func (p Policy) Allows(t protocol.Task) bool {
	ok := false
	for _, v := range p.Allowed {
		if v == t.Type {
			ok = true
		}
	}
	if !ok {
		return false
	}
	switch t.Type {
	case protocol.ServiceStatus:
		id, e := t.Resource()
		_, ok = p.Service(id)
		return e == nil && ok
	case protocol.SSHAudit:
		id, e := t.Resource()
		_, ok = p.SSHProfile(id)
		return e == nil && ok
	}
	return true
}
func (p Policy) Service(id string) (resources.Service, bool) {
	for _, v := range p.Services {
		if v.ID == id {
			return v, true
		}
	}
	return resources.Service{}, false
}
func (p Policy) SSHProfile(id string) (resources.SSHProfile, bool) {
	for _, v := range p.SSHProfiles {
		if v.ID == id {
			return v, true
		}
	}
	return resources.SSHProfile{}, false
}
