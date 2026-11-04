package protocol

import (
	"runtime/debug"
	"strings"
)

const Version = 1
const VersionHeader = "X-Argus-Protocol-Version"
const AgentVersionHeader = "X-Argus-Agent-Version"

type AgentMetadata struct {
	ProtocolVersion int    `json:"protocol_version"`
	AgentVersion    string `json:"agent_version"`
}

func (m AgentMetadata) Valid() bool {
	if m.ProtocolVersion != Version || len(m.AgentVersion) == 0 || len(m.AgentVersion) > 128 {
		return false
	}
	for _, r := range m.AgentVersion {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._+-", r)) {
			return false
		}
	}
	return true
}
func BuildVersion() string {
	name := "development"
	if info, ok := debug.ReadBuildInfo(); ok {
		revision, dirty := "", false
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				revision = s.Value
			}
			if s.Key == "vcs.modified" {
				dirty = s.Value == "true"
			}
		}
		if revision != "" {
			name += "+" + revision[:min(12, len(revision))]
		}
		if dirty {
			name += ".dirty"
		}
	}
	return name
}
