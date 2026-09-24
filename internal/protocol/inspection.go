package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type FileMetadata struct {
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Mode uint32 `json:"mode"`
	Size int64  `json:"size"`
}
type KeyObservation struct {
	Line        int    `json:"line"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	HasOptions  bool   `json:"has_options"`
}
type DirectiveObservation struct {
	Line  int    `json:"line"`
	Name  string `json:"name"`
	Value string `json:"value"`
}
type SSHFileObservation struct {
	ID                string                 `json:"id"`
	Kind              string                 `json:"kind"`
	Status            string                 `json:"status"`
	MetadataAvailable bool                   `json:"metadata_available"`
	Metadata          FileMetadata           `json:"metadata"`
	SHA256            string                 `json:"sha256"`
	Baseline          string                 `json:"baseline"`
	Keys              []KeyObservation       `json:"keys"`
	Directives        []DirectiveObservation `json:"directives"`
	Findings          []string               `json:"findings"`
}
type SSHReport struct {
	ProfileID  string               `json:"profile_id"`
	ObservedAt int64                `json:"observed_at"`
	Coverage   string               `json:"coverage"`
	Files      []SSHFileObservation `json:"files"`
}
type ServiceReport struct {
	ServiceID   string `json:"service_id"`
	ObservedAt  int64  `json:"observed_at"`
	Available   bool   `json:"available"`
	Code        string `json:"code"`
	Unit        string `json:"unit"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func InspectionCode(s string) bool {
	return oneOf(s, "ok", "partial", "missing", "permission_denied", "unsafe_path", "unsafe_type", "owner_mismatch", "too_large", "changed_during_read", "unsupported", "io_error", "parse_error", "sensitive_content")
}
func SSHFinding(s string) bool {
	return oneOf(s, "group_or_other_writable", "match_not_evaluated", "include_not_expanded", "dynamic_auth_not_evaluated", "other_directives_not_evaluated", "invalid_line", "key_options_not_evaluated", "key_certificate_not_evaluated", "key_limit", "line_limit", "duplicate_directive", "empty_key_file", "baseline_changed", "invalid_value", "directive_limit")
}
func DirectiveValue(name, value string) bool {
	if name == "permitrootlogin" {
		return oneOf(value, "yes", "no", "prohibit-password", "without-password", "forced-commands-only")
	}
	if oneOf(name, "passwordauthentication", "pubkeyauthentication", "kbdinteractiveauthentication", "permitemptypasswords", "strictmodes", "usepam") {
		return oneOf(value, "yes", "no")
	}
	return false
}
func (r SSHReport) Validate(now int64) error {
	bad := errors.New("invalid SSH audit result")
	if !ResourceID(r.ProfileID) || r.ObservedAt < 1 || r.ObservedAt > now || !oneOf(r.Coverage, "complete", "partial", "unavailable") || r.Files == nil || len(r.Files) < 1 || len(r.Files) > 4 {
		return bad
	}
	seen := map[string]bool{}
	allOK, anyRead := true, false
	for _, f := range r.Files {
		if !ResourceID(f.ID) || seen[f.ID] || !oneOf(f.Kind, "sshd_config", "authorized_keys") || !InspectionCode(f.Status) || f.Metadata.Mode > 07777 || f.Metadata.Size < 0 || f.Keys == nil || f.Directives == nil || f.Findings == nil || len(f.Keys) > 8 || len(f.Directives) > 8 || len(f.Findings) > 16 {
			return bad
		}
		seen[f.ID] = true
		if !f.MetadataAvailable && f.Metadata != (FileMetadata{}) {
			return bad
		}
		if f.Status != "ok" {
			allOK = false
		}
		if f.Status == "ok" || f.Status == "partial" {
			anyRead = true
			if !f.MetadataAvailable || !identity.Hex(f.SHA256, 64) || !oneOf(f.Baseline, "unconfigured", "match", "changed") {
				return bad
			}
		} else {
			if f.SHA256 != "" || f.Baseline != "unavailable" || len(f.Keys) != 0 || len(f.Directives) != 0 {
				return bad
			}
		}
		if f.Kind == "sshd_config" && len(f.Keys) != 0 || f.Kind == "authorized_keys" && len(f.Directives) != 0 {
			return bad
		}
		for _, k := range f.Keys {
			if k.Line < 1 || k.Line > 512 || k.Type == "" || !CleanText(k.Type, 64) || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
				return bad
			}
			b, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(k.Fingerprint, "SHA256:"))
			if err != nil || len(b) != 32 {
				return bad
			}
		}
		for _, d := range f.Directives {
			if d.Line < 1 || d.Line > 512 || !DirectiveValue(d.Name, d.Value) {
				return bad
			}
		}
		findings := map[string]bool{}
		for _, v := range f.Findings {
			if !SSHFinding(v) || findings[v] {
				return bad
			}
			findings[v] = true
		}
	}
	want := "partial"
	if allOK {
		want = "complete"
	} else if !anyRead {
		want = "unavailable"
	}
	if r.Coverage != want {
		return bad
	}
	return nil
}
func DecodeSSHReport(data []byte, now int64) (SSHReport, error) {
	var raw struct {
		ProfileID  string            `json:"profile_id"`
		ObservedAt int64             `json:"observed_at"`
		Coverage   string            `json:"coverage"`
		Files      []json.RawMessage `json:"files"`
	}
	if err := strictjson.Decode(data, &raw, MaxDispatchResultBytes, "profile_id", "observed_at", "coverage", "files"); err != nil {
		return SSHReport{}, err
	}
	if len(raw.Files) > 4 {
		return SSHReport{}, errors.New("too many SSH observations")
	}
	r := SSHReport{raw.ProfileID, raw.ObservedAt, raw.Coverage, []SSHFileObservation{}}
	for _, data := range raw.Files {
		var f SSHFileObservation
		if err := strictjson.Decode(data, &f, 16384, "id", "kind", "status", "metadata_available", "metadata", "sha256", "baseline", "keys", "directives", "findings"); err != nil {
			return r, err
		}
		var nested struct {
			Metadata   json.RawMessage   `json:"metadata"`
			Keys       []json.RawMessage `json:"keys"`
			Directives []json.RawMessage `json:"directives"`
		}
		if err := json.Unmarshal(data, &nested); err != nil {
			return r, err
		}
		if err := strictjson.Decode(nested.Metadata, &f.Metadata, 256, "uid", "gid", "mode", "size"); err != nil {
			return r, err
		}
		for _, v := range nested.Keys {
			var k KeyObservation
			if err := strictjson.Decode(v, &k, 512, "line", "type", "fingerprint", "has_options"); err != nil {
				return r, err
			}
		}
		for _, v := range nested.Directives {
			var d DirectiveObservation
			if err := strictjson.Decode(v, &d, 256, "line", "name", "value"); err != nil {
				return r, err
			}
		}
		r.Files = append(r.Files, f)
	}
	return r, r.Validate(now)
}
func (r ServiceReport) Validate(now int64) error {
	bad := errors.New("invalid service status result")
	if !ResourceID(r.ServiceID) || r.ObservedAt < 1 || r.ObservedAt > now {
		return bad
	}
	if !r.Available {
		if !oneOf(r.Code, "unsupported", "bus_unavailable", "permission_denied", "unit_not_loaded", "alias_mismatch", "invalid_response") || r.Unit != "" || r.LoadState != "" || r.ActiveState != "" || r.SubState != "" {
			return bad
		}
		return nil
	}
	if r.Code != "" || !CleanText(r.Unit, 128) || !strings.HasSuffix(r.Unit, ".service") || !stateWord(r.LoadState) || !stateWord(r.ActiveState) || !stateWord(r.SubState) {
		return bad
	}
	return nil
}
func stateWord(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c == '-') {
			return false
		}
	}
	return true
}
func DecodeServiceReport(data []byte, now int64) (ServiceReport, error) {
	var r ServiceReport
	if err := strictjson.Decode(data, &r, 2048, "service_id", "observed_at", "available", "code", "unit", "load_state", "active_state", "sub_state"); err != nil {
		return r, err
	}
	return r, r.Validate(now)
}

func (r Result) CheckAssignment(t Task) error {
	if r.RequestID != t.RequestID || r.AgentID != t.AgentID || r.Epoch != t.EnrollmentEpoch || r.Type != t.Type {
		return errors.New("result assignment mismatch")
	}
	if r.Status != Succeeded {
		return nil
	}
	if t.Type == SSHAudit {
		id, err := t.Resource()
		if err != nil {
			return err
		}
		v, err := DecodeSSHReport(r.Data, r.FinishedAt)
		if err != nil {
			return err
		}
		if v.ProfileID != id {
			return errors.New("SSH result profile mismatch")
		}
	}
	if t.Type == ServiceStatus {
		id, err := t.Resource()
		if err != nil {
			return err
		}
		v, err := DecodeServiceReport(r.Data, r.FinishedAt)
		if err != nil {
			return err
		}
		if v.ServiceID != id {
			return errors.New("service result ID mismatch")
		}
	}
	return nil
}
