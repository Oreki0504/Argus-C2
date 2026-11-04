// Package config loads local files with explicit, validated fields.
package config

import (
	"errors"
	"net"
	"path/filepath"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type Server struct {
	Listen      string `json:"listen"`
	StateDir    string `json:"state_dir"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	CA          string `json:"ca"`
	IssuerKey   string `json:"issuer_key"`
	Admins      string `json:"admins"`
}
type Agent struct {
	Server   string `json:"server"`
	CA       string `json:"ca"`
	StateDir string `json:"state_dir"`
	Policy   string `json:"policy"`
}

func paths(paths ...string) error {
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("configuration paths must be canonical absolute paths")
		}
	}
	return nil
}
func LoadServer(path string) (Server, error) {
	var c Server
	b, e := localfile.Read(path, 8192, false)
	if e != nil {
		return c, e
	}
	if e = strictjson.Decode(b, &c, 8192, "listen", "state_dir", "certificate", "private_key", "ca", "issuer_key", "admins"); e != nil {
		return c, e
	}
	if _, _, e = net.SplitHostPort(c.Listen); e != nil {
		return c, e
	}
	return c, paths(c.StateDir, c.Certificate, c.PrivateKey, c.CA, c.IssuerKey, c.Admins)
}
func LoadAgent(path string) (Agent, policy.Policy, error) {
	var c Agent
	b, e := localfile.Read(path, 8192, false)
	if e != nil {
		return c, policy.Policy{}, e
	}
	if e = strictjson.Decode(b, &c, 8192, "server", "ca", "state_dir", "policy"); e != nil {
		return c, policy.Policy{}, e
	}
	if e = transport.ValidateURL(c.Server); e != nil {
		return c, policy.Policy{}, e
	}
	if e = paths(c.CA, c.StateDir, c.Policy); e != nil {
		return c, policy.Policy{}, e
	}
	p, e := policy.Load(c.Policy)
	return c, p, e
}
