// Package resources defines locally administered mappings, never network paths.
package resources

import (
	"encoding/json"
	"errors"
	"path"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxProfiles = 4
const MaxFiles = 4
const MaxServices = 16

type SSHFile struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	BaseDir        string `json:"base_dir"`
	RelativePath   string `json:"relative_path"`
	OwnerUID       uint32 `json:"owner_uid"`
	OwnerGID       uint32 `json:"owner_gid"`
	MaxBytes       int    `json:"max_bytes"`
	BaselineSHA256 string `json:"baseline_sha256"`
}
type SSHProfile struct {
	ID    string    `json:"id"`
	Files []SSHFile `json:"files"`
}
type Service struct {
	ID   string `json:"id"`
	Unit string `json:"unit"`
}

func UnitName(s string) bool {
	if len(s) > 128 || !strings.HasSuffix(s, ".service") || len(s) <= len(".service") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.@-", c)) {
			return false
		}
	}
	return !strings.Contains(s, "..") && !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, "@.service")
}
func (f SSHFile) Validate() error {
	bad := errors.New("invalid local SSH file mapping")
	if !protocol.ResourceID(f.ID) || !protocol.CleanText(f.BaseDir, 256) || !strings.HasPrefix(f.BaseDir, "/") || path.Clean(f.BaseDir) != f.BaseDir || !protocol.CleanText(f.RelativePath, 256) || f.RelativePath == "" || strings.HasPrefix(f.RelativePath, "/") || path.Clean(f.RelativePath) != f.RelativePath || f.MaxBytes < 1024 || f.MaxBytes > 65536 {
		return bad
	}
	for _, part := range strings.Split(f.RelativePath, "/") {
		if part == "." || part == ".." || strings.ContainsAny(part, "\\*?[]%~") {
			return bad
		}
	}
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/run"} {
		if f.BaseDir == prefix || strings.HasPrefix(f.BaseDir, prefix+"/") {
			return bad
		}
	}
	name := path.Base(f.RelativePath)
	switch f.Kind {
	case "sshd_config":
		if name != "sshd_config" && !(strings.HasSuffix(name, ".conf") && strings.Contains("/"+f.RelativePath, "/sshd_config.d/")) {
			return bad
		}
	case "authorized_keys":
		if name != "authorized_keys" && name != "authorized_keys2" {
			return bad
		}
	default:
		return bad
	}
	if f.BaselineSHA256 != "" && !identity.Hex(f.BaselineSHA256, 64) {
		return bad
	}
	return nil
}
func (p SSHProfile) Validate() error {
	if !protocol.ResourceID(p.ID) || p.Files == nil || len(p.Files) < 1 || len(p.Files) > MaxFiles {
		return errors.New("invalid local SSH profile")
	}
	ids, paths := map[string]bool{}, map[string]bool{}
	for _, f := range p.Files {
		if err := f.Validate(); err != nil {
			return err
		}
		full := path.Join(f.BaseDir, f.RelativePath)
		if ids[f.ID] || paths[full] {
			return errors.New("duplicate SSH file mapping")
		}
		ids[f.ID] = true
		paths[full] = true
	}
	return nil
}
func (s Service) Validate() error {
	if !protocol.ResourceID(s.ID) || !UnitName(s.Unit) {
		return errors.New("invalid local service mapping")
	}
	return nil
}
func DecodeProfile(data []byte) (SSHProfile, error) {
	var raw struct {
		ID    string            `json:"id"`
		Files []json.RawMessage `json:"files"`
	}
	if err := strictjson.Decode(data, &raw, 16384, "id", "files"); err != nil {
		return SSHProfile{}, err
	}
	if len(raw.Files) > MaxFiles {
		return SSHProfile{}, errors.New("too many SSH files")
	}
	p := SSHProfile{ID: raw.ID, Files: []SSHFile{}}
	for _, b := range raw.Files {
		var f SSHFile
		if err := strictjson.Decode(b, &f, 2048, "id", "kind", "base_dir", "relative_path", "owner_uid", "owner_gid", "max_bytes", "baseline_sha256"); err != nil {
			return SSHProfile{}, err
		}
		p.Files = append(p.Files, f)
	}
	return p, p.Validate()
}
func DecodeService(data []byte) (Service, error) {
	var s Service
	if err := strictjson.Decode(data, &s, 512, "id", "unit"); err != nil {
		return s, err
	}
	return s, s.Validate()
}
