package console

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
)

// Opt-in browser harness. All credentials, TLS certificates and OIDC identities
// are isolated test values. The production server has no test login endpoint.
func TestConsoleBrowserHarness(t *testing.T) {
	infoFile := os.Getenv("ARGUS_CONSOLE_BROWSER_INFO")
	if infoFile == "" {
		t.Skip("opt-in browser harness")
	}
	dir := filepath.Join(t.TempDir(), "state")
	store, err := database.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	https := httptest.NewUnstartedServer(nil)
	_, port, err := net.SplitHostPort(https.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// localhost (Console) and 127.0.0.1 (IdP) are distinct sites, exercising
	// SameSite cookies across an actual cross-site authorization redirect.
	origin := "https://localhost:" + port
	s, err := New(store, Config{Origin: origin, StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProvider(t)
	enableTestInstaller(t, s)
	if artifacts := os.Getenv("ARGUS_CONSOLE_TEST_ARTIFACTS"); artifacts != "" {
		s.config.InstallerDir = artifacts
		s.installer, err = loadInstaller(s.config)
		if err != nil {
			t.Fatal(err)
		}
	}
	p.redirectURI = origin + "/v1/console/auth/callback"
	s.httpClient = p.server.Client()
	s.httpClient.Timeout = 10 * time.Second
	s.httpClient.Transport = boundedTransport{s.httpClient.Transport}
	https.Config.Handler = s.Handler()
	https.StartTLS()
	defer https.Close()
	secret, err := store.IssueConsoleToken(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	info := map[string]string{"origin": origin, "issuer": p.server.URL, "client_id": "console-test", "client_secret": "test-secret", "bootstrap": secret}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(infoFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(infoFile)
	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("browser harness timed out")
		case <-tick.C:
			if _, err := os.Stat(infoFile + ".done"); err == nil {
				_ = os.Remove(infoFile + ".done")
				return
			}
		}
	}
}
