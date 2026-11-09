package collector

import (
	"path/filepath"
	"regexp"
	"strings"
)

var releaseVersion = regexp.MustCompile(`^[0-9]{1,4}(?:\.[0-9]{1,4}){0,2}$`)

// Match the Console's public OS vocabulary and keep within the protocol's
// 32-byte OS limit. ID_LIKE describes ancestry, not the installed distribution.
var distributionNames = map[string]string{
	"ubuntu":              "Ubuntu",
	"debian":              "Debian",
	"fedora":              "Fedora",
	"alpine":              "Alpine",
	"arch":                "Arch",
	"rocky":               "Rocky",
	"almalinux":           "AlmaLinux",
	"centos":              "CentOS",
	"rhel":                "Red Hat",
	"opensuse":            "openSUSE",
	"opensuse-leap":       "openSUSE",
	"opensuse-tumbleweed": "openSUSE",
	"sles":                "SUSE",
	"sled":                "SUSE",
	"amzn":                "Amazon Linux",
	"ol":                  "Oracle Linux",
	"nixos":               "NixOS",
}

func linuxDistribution(paths ...string) string {
	for _, path := range paths {
		// os-release is commonly a symlink. Resolve these fixed local paths,
		// then retain readFixed's regular-file check and bounded read.
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		if raw := readFixed(resolved, 16*1024); raw != "" {
			return parseOSRelease(raw)
		}
	}
	return "linux"
}

func parseOSRelease(raw string) string {
	var id, version string
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (key != "ID" && key != "VERSION_ID") {
			continue
		}
		value = strings.TrimSpace(value)
		// These fields only need literal IDs and numeric versions. Never
		// source the file or evaluate shell expansions/escape sequences.
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if key == "ID" {
			id = value
		} else {
			version = value
		}
	}
	name, ok := distributionNames[id]
	if !ok {
		return "linux"
	}
	if releaseVersion.MatchString(version) {
		name += " " + version
	}
	return name
}
