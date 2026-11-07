package console

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

// Minimal ELF header for loader tests, never executed. Real published binaries
// are built separately with deploy/linux/build-agent-artifacts.sh.
func testELF(machine uint16) []byte {
	b := make([]byte, 120)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint64(b[96:], 120)
	binary.LittleEndian.PutUint64(b[104:], 120)
	return b
}
func installerConfig(t *testing.T, c Config) (Config, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "pki")
	if err := enrollment.Initialize(root, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	c.FleetCA = filepath.Join(root, "ca.pem")
	c.FleetOrigin = "https://fleet.example:8443"
	c.InstallerDir = t.TempDir()
	for arch, machine := range map[string]uint16{"amd64": 62, "arm64": 183} {
		if err := os.WriteFile(filepath.Join(c.InstallerDir, "agent-linux-"+arch), testELF(machine), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return c, root
}
func enableTestInstaller(t *testing.T, s *Server) string {
	t.Helper()
	c, root := installerConfig(t, s.config)
	i, err := loadInstaller(c)
	if err != nil {
		t.Fatal(err)
	}
	s.config, s.installer = c, i
	return root
}
func newInstallation(t *testing.T, admin *testBrowser) installation {
	t.Helper()
	return decodeTest[installation](t, admin.request("POST", "/v1/console/admin/installations", map[string]int{"ttl_seconds": 900}, admin.identity()["csrf_token"].(string), nil), 200)
}
func installPath(t *testing.T, v installation) string {
	t.Helper()
	u, err := url.Parse(v.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Path
}

func TestInstallerConfigurationAndSnapshots(t *testing.T) {
	c, _ := installerConfig(t, Config{Origin: "https://console.example"})
	i, err := loadInstaller(c)
	if err != nil || len(i.artifacts) != 2 {
		t.Fatal(err)
	}
	// Replacement on disk has no effect until a deliberate server restart.
	path := filepath.Join(c.InstallerDir, "agent-linux-amd64")
	if err := os.WriteFile(path, []byte("replaced"), 0644); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(i.artifacts["amd64"].data, testELF(62)) {
		t.Fatal("artifact changed")
	}
	if _, err := loadInstaller(c); err == nil {
		t.Fatal("non-ELF accepted")
	}
	if err := os.WriteFile(path, testELF(183), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstaller(c); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstaller(c); err != nil {
		t.Fatal("one supported architecture must work", err)
	}
	if err := os.Symlink(filepath.Join(c.InstallerDir, "agent-linux-arm64"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstaller(c); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, origin := range []string{"http://fleet.example", "https://fleet.example/", "https://fleet.example'", "https://fleet.example?foo=bar", "https://:8443", "https://0.0.0.0:8443", "https://[::]:8443"} {
		bad := c
		bad.FleetOrigin = origin
		if _, err := loadInstaller(bad); err == nil {
			t.Fatal("invalid origin", origin)
		}
	}
	if i, err := loadInstaller(Config{}); i != nil || err != nil {
		t.Fatal("optional installer required")
	}
	if _, err := loadInstaller(Config{InstallerDir: c.InstallerDir}); err == nil {
		t.Fatal("partial config accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.FleetCA = strings.TrimSuffix(c.FleetCA, "ca.pem") + "ca-key.pem"
	if _, err := loadInstaller(c); err == nil {
		t.Fatal("private CA key accepted")
	}
}

func TestInstallationAuthorizationOneUseAndEnrollment(t *testing.T) {
	s, _, admin := testConsole(t)
	ctx := context.Background()
	csrf := admin.identity()["csrf_token"].(string)
	if status := decodeTest[installerStatus](t, admin.request("GET", "/v1/console/admin/installer", nil, "", nil), 200); status.Enabled {
		t.Fatal(status)
	}
	decodeTest[map[string]string](t, admin.request("POST", "/v1/console/admin/installations", map[string]int{"ttl_seconds": 900}, csrf, nil), 409)
	root := enableTestInstaller(t, s)
	status := decodeTest[installerStatus](t, admin.request("GET", "/v1/console/admin/installer", nil, "", nil), 200)
	if !status.Enabled || len(status.Platforms) != 2 {
		t.Fatal(status)
	}
	guest := newBrowser(t, s)
	decodeTest[map[string]string](t, guest.request("POST", "/v1/console/admin/installations", map[string]int{"ttl_seconds": 900}, csrf, nil), 401)
	for _, ttl := range []int{0, 59, 3601} {
		decodeTest[map[string]string](t, admin.request("POST", "/v1/console/admin/installations", map[string]int{"ttl_seconds": ttl}, csrf, nil), 400)
	}
	decodeTest[map[string]string](t, admin.request("POST", "/v1/console/admin/installations", map[string]int{"ttl_seconds": 900}, "wrong", nil), 403)
	decodeTest[map[string]string](t, admin.request("POST", "/v1/console/admin/installations", map[string]int{"ttl_seconds": 900}, csrf, map[string]string{"Origin": "https://other.example"}), 403)
	link := newInstallation(t, admin)
	path := installPath(t, link)
	var token string
	for key, ticket := range s.installer.tickets {
		if key != database.TokenDigest(strings.TrimPrefix(path, "/v1/console/install/")) {
			t.Fatal("ticket not hashed")
		}
		token = ticket.token
	}
	decodeTest[map[string]string](t, guest.request("HEAD", path, nil, "", nil), 405)
	decodeTest[map[string]string](t, guest.request("GET", path, nil, "", map[string]string{"Sec-Fetch-Mode": "navigate"}), 400)
	responses := make(chan int, 8)
	scripts := make(chan string, 8)
	for range 8 {
		go func() {
			w := guest.request("GET", path, nil, "", nil)
			responses <- w.Code
			if w.Code == 200 {
				scripts <- w.Body.String()
			}
		}()
	}
	ok := 0
	for range 8 {
		if code := <-responses; code == 200 {
			ok++
		} else if code != 404 {
			t.Fatal(code)
		}
	}
	if ok != 1 {
		t.Fatalf("%d successful redemptions", ok)
	}
	script := <-scripts
	if !strings.Contains(script, token) || strings.Contains(script, "{{") {
		t.Fatal("incomplete rendering")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(script)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
	}
	issuer, err := enrollment.Load(filepath.Join(root, "ca.pem"), filepath.Join(root, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := enrollment.CSR(key)
	if err != nil {
		t.Fatal(err)
	}
	service := enrollment.Service{Store: s.store, Issuer: issuer}
	request := protocol.EnrollmentRequest{Token: token, Hostname: "installed-test", CSR: csr}
	metadata := protocol.AgentMetadata{ProtocolVersion: protocol.Version, AgentVersion: "test"}
	registered, err := service.Enroll(ctx, request, metadata)
	if err != nil || registered.NodeID == "" {
		t.Fatal("installer token cannot enroll", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request.CSR, _ = enrollment.CSR(other)
	if _, err := service.Enroll(ctx, request, metadata); err == nil {
		t.Fatal("token enrolled another host")
	}
	for arch, a := range s.installer.artifacts {
		w := guest.request("GET", "/v1/console/install/assets/"+arch+"/"+a.hash, nil, "", nil)
		hash := sha256.Sum256(w.Body.Bytes())
		if w.Code != 200 || hex.EncodeToString(hash[:]) != a.hash || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("artifact mismatch")
		}
	}
	decodeTest[map[string]string](t, guest.request("GET", "/v1/console/install/assets/amd64/wrong", nil, "", nil), 404)
	audit := admin.request("GET", "/v1/console/admin/audit", nil, "", nil).Body.String()
	if strings.Contains(audit, token) || strings.Contains(audit, path) || !strings.Contains(audit, "console.installation.redeem") {
		t.Fatal("audit disclosure or missing redemption")
	}
}

func TestInstallationExpiryRevocationAndUserBoundary(t *testing.T) {
	s, p, admin := testConsole(t)
	enableTestInstaller(t, s)
	me := admin.identity()
	link := newInstallation(t, admin)
	guest := newBrowser(t, s)
	s.now = func() time.Time { return time.Unix(link.Expires, 0) }
	decodeTest[map[string]string](t, guest.request("GET", installPath(t, link), nil, "", nil), 404)
	s.now = time.Now
	link = newInstallation(t, admin)
	if err := s.store.RevokeConsoleSessions(context.Background(), "test", me["principal_id"].(string)); err != nil {
		t.Fatal(err)
	}
	decodeTest[map[string]string](t, guest.request("GET", installPath(t, link), nil, "", nil), 404)
	// A separately approved ordinary User still cannot mint installation credentials.
	p.subject = "ordinary"
	user := newBrowser(t, s)
	user.login(p)
	if _, err := s.store.DB.Exec("UPDATE console_users SET status='active' WHERE subject='ordinary'"); err != nil {
		t.Fatal(err)
	}
	user.login(p)
	csrf := user.identity()["csrf_token"].(string)
	decodeTest[map[string]string](t, user.request("GET", "/v1/console/admin/installer", nil, "", nil), 403)
	decodeTest[map[string]string](t, user.request("POST", "/v1/console/admin/installations", map[string]int{"ttl_seconds": 900}, csrf, nil), 403)
}

func TestInstallerTemplateMatchesDeploymentAndLocalPolicy(t *testing.T) {
	unit, err := os.ReadFile("../../deploy/linux/argus-c2-agent.service")
	if err != nil || string(unit) != installUnit {
		t.Fatal("embedded service drifted", err)
	}
	s, _, _ := testConsole(t)
	enableTestInstaller(t, s)
	script := s.renderInstallation(installTicket{token: "TEST", expires: time.Now().Add(time.Hour).Unix()})
	for _, marker := range []string{"ARGUS_AGENT_CONFIG", "ARGUS_AGENT_POLICY"} {
		parts := strings.Split(script, "<<'"+marker+"'\n")
		if len(parts) != 2 {
			t.Fatal(marker)
		}
		data := strings.Split(parts[1], "\n"+marker)[0]
		if !json.Valid([]byte(data)) {
			t.Fatal("invalid JSON heredoc", marker)
		}
	}
}
