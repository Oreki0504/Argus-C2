// Package sshaudit produces bounded observations, never effective sshd policy.
package sshaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
	"github.com/Oreki0504/Argus-C2/internal/saferead"
	"golang.org/x/crypto/ssh"
)

func Collect(ctx context.Context, p resources.SSHProfile) (protocol.SSHReport, error) {
	if err := p.Validate(); err != nil {
		return protocol.SSHReport{}, err
	}
	r := protocol.SSHReport{ProfileID: p.ID, ObservedAt: time.Now().Unix(), Coverage: "complete", Files: []protocol.SSHFileObservation{}}
	anyRead := false
	for _, mapping := range p.Files {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		observation := saferead.Read(ctx, mapping)
		f := protocol.SSHFileObservation{ID: mapping.ID, Kind: mapping.Kind, Status: observation.Code, MetadataAvailable: observation.MetadataAvailable, Metadata: observation.Metadata, Baseline: "unavailable", Keys: []protocol.KeyObservation{}, Directives: []protocol.DirectiveObservation{}, Findings: []string{}}
		if f.MetadataAvailable && f.Metadata.Mode&0022 != 0 {
			finding(&f, "group_or_other_writable")
		}
		if observation.Code == "ok" {
			parse(observation.Data, &f)
			if f.Status == "ok" || f.Status == "partial" {
				anyRead = true
				digest := sha256.Sum256(observation.Data)
				f.SHA256 = hex.EncodeToString(digest[:])
				f.Baseline = "unconfigured"
				if mapping.BaselineSHA256 != "" {
					f.Baseline = "match"
					if mapping.BaselineSHA256 != f.SHA256 {
						f.Baseline = "changed"
						finding(&f, "baseline_changed")
					}
				}
			}
		}
		if f.Status != "ok" {
			r.Coverage = "partial"
		}
		r.Files = append(r.Files, f)
	}
	if !anyRead {
		r.Coverage = "unavailable"
	}
	return r, ctx.Err()
}
func finding(f *protocol.SSHFileObservation, code string) {
	for _, v := range f.Findings {
		if v == code {
			return
		}
	}
	f.Findings = append(f.Findings, code)
}
func partial(f *protocol.SSHFileObservation, code string) {
	if f.Status == "ok" {
		f.Status = "partial"
	}
	finding(f, code)
}
func parse(data []byte, f *protocol.SSHFileObservation) {
	if len(data) > 65536 || !utf8.Valid(data) || bytes.Contains(data, []byte("PRIVATE KEY")) {
		f.Status = "sensitive_content"
		return
	}
	for _, b := range data {
		if b < 32 && b != '\r' && b != '\n' && b != '\t' || b == 127 {
			f.Status = "parse_error"
			return
		}
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 513 || len(lines) == 513 && len(lines[512]) != 0 {
		f.Status = "parse_error"
		finding(f, "line_limit")
		return
	}
	matched := false
	seen := map[string]bool{}
	for i, raw := range lines {
		raw = bytes.TrimSuffix(raw, []byte{'\r'})
		if bytes.IndexByte(raw, '\r') >= 0 {
			f.Status = "parse_error"
			finding(f, "invalid_line")
			break
		}
		if len(raw) > 8192 {
			f.Status = "parse_error"
			finding(f, "line_limit")
			break
		}
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if f.Kind == "authorized_keys" {
			key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil || len(bytes.TrimSpace(rest)) != 0 {
				f.Status = "parse_error"
				finding(f, "invalid_line")
				break
			}
			if len(f.Keys) >= 8 {
				partial(f, "key_limit")
				continue
			}
			f.Keys = append(f.Keys, protocol.KeyObservation{Line: i + 1, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), HasOptions: len(options) > 0})
			if len(options) > 0 {
				partial(f, "key_options_not_evaluated")
			}
			if _, ok := key.(*ssh.Certificate); ok {
				partial(f, "key_certificate_not_evaluated")
			}
			continue
		}
		// Deliberately observe only simple literal values. No glob expansion,
		// token substitution, default evaluation, Include traversal, or commands.
		fields := strings.Fields(line)
		name := strings.ToLower(fields[0])
		if strings.ContainsAny(name, "=\"'\\") {
			f.Status = "parse_error"
			finding(f, "invalid_line")
			break
		}
		for _, c := range name {
			if c < 'a' || c > 'z' {
				f.Status = "parse_error"
				finding(f, "invalid_line")
				break
			}
		}
		if f.Status == "parse_error" {
			break
		}
		if len(fields) < 2 {
			f.Status = "parse_error"
			finding(f, "invalid_line")
			break
		}
		switch name {
		case "match":
			matched = true
			partial(f, "match_not_evaluated")
			continue
		case "include":
			partial(f, "include_not_expanded")
			continue
		case "authorizedkeyscommand", "authorizedprincipalscommand", "authorizedkeysfile", "authorizedprincipalsfile", "trustedusercakeys":
			partial(f, "dynamic_auth_not_evaluated")
			continue
		}
		if matched {
			continue
		}
		if name == "challengeresponseauthentication" {
			name = "kbdinteractiveauthentication"
		}
		value := fields[1]
		if !protocol.DirectiveValue(name, value) {
			partial(f, "other_directives_not_evaluated")
			continue
		}
		if len(fields) != 2 {
			partial(f, "invalid_value")
			continue
		}
		if seen[name] {
			partial(f, "duplicate_directive")
			continue
		}
		seen[name] = true
		if len(f.Directives) >= 8 {
			partial(f, "directive_limit")
			continue
		}
		f.Directives = append(f.Directives, protocol.DirectiveObservation{Line: i + 1, Name: name, Value: value})
	}
	if f.Status == "parse_error" {
		f.Keys = []protocol.KeyObservation{}
		f.Directives = []protocol.DirectiveObservation{}
	}
	if f.Kind == "authorized_keys" && f.Status == "ok" && len(f.Keys) == 0 {
		finding(f, "empty_key_file")
	}
}
