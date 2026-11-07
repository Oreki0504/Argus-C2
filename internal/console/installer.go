package console

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

//go:embed installer/script.sh
var installScript string

//go:embed installer/argus-c2-agent.service
var installUnit string

type installArtifact struct {
	data []byte // Immutable snapshot: replacing a file cannot change an issued download.
	hash string
}
type installTicket struct {
	id, userID, token            string
	version, generation, expires int64
}
type installer struct {
	artifacts map[string]installArtifact
	ca        string
	mu        sync.Mutex
	tickets   map[string]installTicket // Only the URL credential's digest is retained.
}
type installerStatus struct {
	Enabled     bool     `json:"enabled"`
	Platforms   []string `json:"platforms"`
	FleetOrigin string   `json:"fleet_origin"`
}
type installation struct {
	ID      string `json:"installation_id"`
	URL     string `json:"url"`
	Expires int64  `json:"expires_at"`
}

// Origins appear in a shell literal and JSON heredoc. Accept canonical DNS/IP
// origins only, with no escapes, user info, path, query or shell metacharacters.
var installOrigin = regexp.MustCompile(`^https://[a-z0-9.\[\]:-]+$`)

func loadInstaller(c Config) (*installer, error) {
	if c.InstallerDir == "" && c.FleetOrigin == "" {
		return nil, nil
	}
	if c.InstallerDir == "" || c.FleetOrigin == "" || c.FleetCA == "" {
		return nil, errors.New("installer requires an artifact directory, Fleet origin and Fleet CA")
	}
	for _, origin := range []string{c.Origin, c.FleetOrigin} {
		if err := transport.ValidateURL(origin); err != nil || !installOrigin.MatchString(origin) {
			return nil, errors.New("installer requires canonical HTTPS origins")
		}
		u, _ := url.Parse(origin)
		if u.Hostname() == "" || net.ParseIP(u.Hostname()).IsUnspecified() {
			return nil, errors.New("installer requires a reachable hostname or IP, not an unspecified listen address")
		}
	}
	if !filepath.IsAbs(c.InstallerDir) || filepath.Clean(c.InstallerDir) != c.InstallerDir {
		return nil, errors.New("installer artifact directory must be a canonical absolute path")
	}
	dir, err := os.Lstat(c.InstallerDir)
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("installer artifact directory must be a non-symlink directory")
	}
	i := &installer{artifacts: map[string]installArtifact{}, tickets: map[string]installTicket{}}
	for _, arch := range []string{"amd64", "arm64"} {
		data, err := localfile.Read(filepath.Join(c.InstallerDir, "agent-linux-"+arch), 32<<20, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("installer %s artifact: %w", arch, err)
		}
		if err := validateArtifact(data, arch); err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		i.artifacts[arch] = installArtifact{data, hex.EncodeToString(hash[:])}
	}
	if len(i.artifacts) == 0 {
		return nil, errors.New("installer requires at least one published Linux Agent binary")
	}
	b, err := localfile.Read(c.FleetCA, 65536, false)
	if err != nil {
		return nil, err
	}
	// Re-encode only CA certificates; never embed private keys or arbitrary PEM text.
	for len(bytes.TrimSpace(b)) > 0 {
		var block *pem.Block
		if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("installer Fleet CA must contain only CA certificates")
		}
		block, b = pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid installer Fleet CA")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
			return nil, errors.New("invalid installer Fleet CA")
		}
		i.ca += string(pem.EncodeToMemory(block))
	}
	if i.ca == "" {
		return nil, errors.New("empty installer Fleet CA")
	}
	return i, nil
}

func validateArtifact(data []byte, arch string) error {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("invalid installer ELF: %w", err)
	}
	defer f.Close()
	expected := elf.EM_X86_64
	if arch == "arm64" {
		expected = elf.EM_AARCH64
	}
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != expected || f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return errors.New("installer binary does not match its Linux architecture")
	}
	loadable := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("installer requires a static Agent binary (CGO_ENABLED=0)")
		}
		if p.Type == elf.PT_LOAD {
			loadable = true
		}
	}
	if !loadable {
		return errors.New("installer ELF has no loadable segment")
	}
	return nil
}

func (s *Server) installerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/console/admin/installer", s.authorized(true, s.installerStatus))
	mux.HandleFunc("POST /v1/console/admin/installations", s.authorized(true, s.createInstallation))
	mux.HandleFunc("GET /v1/console/install/{ticket}", s.redeemInstallation)
	mux.HandleFunc("GET /v1/console/install/assets/{arch}/{hash}", s.installAsset)
}

func (s *Server) installerStatus(w http.ResponseWriter, _ *http.Request, _ database.ConsoleUser, _ session) {
	status := installerStatus{Platforms: []string{}}
	if s.installer != nil {
		status.Enabled, status.FleetOrigin = true, s.config.FleetOrigin
		for _, arch := range []string{"amd64", "arm64"} {
			if _, ok := s.installer.artifacts[arch]; ok {
				status.Platforms = append(status.Platforms, "linux/"+arch)
			}
		}
	}
	reply(w, status)
}

func (s *Server) createInstallation(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, v session) {
	var b struct {
		TTL int `json:"ttl_seconds"`
	}
	if !decode(w, r, &b, "ttl_seconds") {
		return
	}
	if b.TTL < 60 || b.TTL > 3600 {
		problem(w, 400, "invalid_request")
		return
	}
	i := s.installer
	if i == nil {
		problem(w, 409, "installer_unavailable")
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	for key, ticket := range i.tickets {
		if s.now().Unix() >= ticket.expires {
			delete(i.tickets, key)
		}
	}
	if len(i.tickets) >= 128 {
		problem(w, 429, "rate_limited")
		return
	}
	token, err := s.store.CreateToken(r.Context(), "web:"+u.ID, time.Duration(b.TTL)*time.Second)
	if err != nil {
		storeProblem(w, err)
		return
	}
	var expires int64
	if err = s.store.DB.QueryRowContext(r.Context(), "SELECT expires_at FROM enrollment_tokens WHERE digest=?", database.TokenDigest(token)).Scan(&expires); err != nil {
		storeProblem(w, err)
		return
	}
	ticket := installTicket{id: identity.RandomID(), userID: u.ID, version: u.Version, generation: v.Generation, token: token, expires: expires}
	if err = s.store.ConsoleAudit(r.Context(), "web:"+u.ID, "console.installation.create", ticket.id, "succeeded"); err != nil {
		storeProblem(w, err)
		return
	}
	raw := identity.RandomID() + identity.RandomID()
	i.tickets[database.TokenDigest(raw)] = ticket
	reply(w, installation{ticket.id, s.config.Origin + "/v1/console/install/" + raw, expires})
}

func (s *Server) redeemInstallation(w http.ResponseWriter, r *http.Request) {
	// A HEAD request or browser prefetch must not burn a command. No redirects.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		problem(w, 405, "invalid_request")
		return
	}
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(r.Header.Get("Purpose"), "prefetch") || strings.Contains(r.Header.Get("Sec-Purpose"), "prefetch") {
		problem(w, 400, "invalid_request")
		return
	}
	i := s.installer
	if i == nil || r.URL.RawQuery != "" || !identity.Valid(r.PathValue("ticket")) {
		problem(w, 404, "installation_unavailable")
		return
	}
	key := database.TokenDigest(r.PathValue("ticket"))
	i.mu.Lock()
	ticket, ok := i.tickets[key]
	delete(i.tickets, key) // Atomic single redemption, including concurrent clients.
	i.mu.Unlock()
	if !ok || s.now().Unix() >= ticket.expires {
		problem(w, 404, "installation_unavailable")
		return
	}
	// Transactional authority check invalidates unredeemed links after account
	// disable, role change, session revocation or Console recovery.
	ctx := database.WithConsoleActor(r.Context(), ticket.userID, ticket.version, ticket.generation, true)
	if err := s.store.ConsoleAudit(ctx, "web:"+ticket.userID, "console.installation.redeem", ticket.id, "succeeded"); err != nil {
		if errors.Is(err, database.ErrUnauthorized) {
			problem(w, 404, "installation_unavailable")
		} else {
			storeProblem(w, err)
		}
		return
	}
	script := s.renderInstallation(ticket)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="argus-install.sh"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	_, _ = w.Write([]byte(script))
}

func (s *Server) renderInstallation(ticket installTicket) string {
	i := s.installer
	c, _ := json.MarshalIndent(config.Agent{Server: s.config.FleetOrigin, CA: "/etc/argus-c2/ca.pem", StateDir: "/var/lib/argus-c2-agent", Policy: "/etc/argus-c2/policy.json"}, "", "  ")
	p, _ := json.MarshalIndent(policy.Default(), "", "  ")
	return strings.NewReplacer("{{AMD64_HASH}}", i.artifacts["amd64"].hash, "{{ARM64_HASH}}", i.artifacts["arm64"].hash,
		"{{ORIGIN}}", s.config.Origin, "{{EXPIRES}}", strconv.FormatInt(ticket.expires, 10),
		"{{AGENT_CONFIG}}", string(c), "{{POLICY}}", string(p), "{{FLEET_CA}}", strings.TrimSpace(i.ca),
		"{{UNIT}}", strings.TrimSpace(installUnit), "{{TOKEN}}", ticket.token).Replace(installScript)
}

func (s *Server) installAsset(w http.ResponseWriter, r *http.Request) {
	if s.installer == nil || r.URL.RawQuery != "" {
		problem(w, 404, "not_found")
		return
	}
	a, ok := s.installer.artifacts[r.PathValue("arch")]
	if !ok || a.hash != r.PathValue("hash") {
		problem(w, 404, "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="agent-linux-`+r.PathValue("arch")+`"`)
	http.ServeContent(w, r, "agent", time.Time{}, bytes.NewReader(a.data))
}
