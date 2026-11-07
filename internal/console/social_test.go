package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/database"
)

// Only this test transport reroutes the fixed social provider hosts.
type socialTransport struct {
	base   http.RoundTripper
	routes map[string]string
}

func (t socialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if target, ok := t.routes[r.URL.Host]; ok {
		destination, _ := url.Parse(target)
		r = r.Clone(r.Context())
		copyURL := *r.URL
		copyURL.Scheme, copyURL.Host = destination.Scheme, destination.Host
		r.URL, r.Host = &copyURL, destination.Host
	}
	return t.base.RoundTrip(r)
}

func socialConsole(t *testing.T) (*Server, *testProvider, *githubFixture, *testBrowser, string, providerSettings) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := database.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	s, err := New(store, Config{Origin: "https://console.example", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	google, github := newTestProvider(t), newGitHubFixture(t)
	google.issuer = googleIssuer
	google.redirectURI = s.config.Origin + callbackPath("google")
	s.httpClient = google.server.Client()
	s.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }
	s.httpClient.Transport = boundedTransport{socialTransport{s.httpClient.Transport, map[string]string{
		"accounts.google.com": google.server.URL, "github.com": github.server.URL, "api.github.com": github.server.URL,
	}}}
	b := newBrowser(t, s)
	secret, err := store.IssueConsoleBootstrap(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	setup := decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/prove", map[string]string{"secret": secret}, b.pre(), nil), 200)
	settings := providerSettings{Providers: []providerCredentials{
		{Kind: "google", ClientID: "console-test", ClientSecret: "test-secret"},
		{Kind: "github", ClientID: "github-test", ClientSecret: "github-secret"},
	}}
	return s, google, github, b, setup["csrf_token"].(string), settings
}
func startSocial(t *testing.T, b *testBrowser, kind, csrf string, setup bool) string {
	route := "/v1/console/auth/login"
	if setup {
		route = "/v1/console/setup/bind"
	}
	decodeTest[map[string]any](t, b.request("POST", route, map[string]string{"provider": kind}, csrf, nil), 200)
	w := b.request("GET", "/v1/console/auth/redirect", nil, "", nil)
	if w.Code != 303 {
		t.Fatalf("no redirect: %d", w.Code)
	}
	client := *b.s.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatalf("upstream authorization failed: %d", resp.StatusCode)
	}
	callback, _ := url.Parse(resp.Header.Get("Location"))
	return callback.RequestURI()
}
func mustConsoleState(t *testing.T, s *Server) database.ConsoleState {
	t.Helper()
	state, err := s.store.ConsoleState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestProviderSelectionAndSavedSecretBoundaries(t *testing.T) {
	s, _, _, b, csrf, settings := socialConsole(t)
	decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/provider", settings, csrf, nil), 200)
	before := mustConsoleState(t, s).ProviderID
	bad := []any{
		providerSettings{},
		providerSettings{Providers: []providerCredentials{settings.Providers[1], settings.Providers[1]}},
		providerSettings{Providers: []providerCredentials{{Kind: "github", Issuer: "https://attacker.example", ClientID: "id", ClientSecret: "secret"}}},
		map[string]any{"providers": []map[string]string{{"kind": "github", "issuer": "", "client_id": "id", "client_secret": "secret", "token_url": "https://attacker.example"}}},
	}
	for _, body := range bad {
		if w := b.request("POST", "/v1/console/setup/provider", body, csrf, nil); w.Code != 400 {
			t.Fatalf("invalid settings accepted: %d", w.Code)
		}
	}
	if mustConsoleState(t, s).ProviderID != before {
		t.Fatal("invalid update changed settings")
	}
	if w := b.request("POST", "/v1/console/setup/bind", map[string]string{"provider": "oidc"}, csrf, nil); w.Code == 200 {
		t.Fatal("unconfigured provider selected")
	}
	for i := range settings.Providers {
		settings.Providers[i].ClientSecret = ""
	}
	decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/provider", settings, csrf, nil), 200)
	current := mustConsoleState(t, s).ProviderID
	saved, err := s.readProvider(current)
	if err != nil || saved[0].ClientSecret != "test-secret" || saved[1].ClientSecret != "github-secret" {
		t.Fatal("saved secret was lost", err)
	}
	settings.Providers[1].ClientID = "changed-client"
	if w := b.request("POST", "/v1/console/setup/provider", settings, csrf, nil); w.Code == 200 {
		t.Fatal("secret reused for another client")
	}
	if mustConsoleState(t, s).ProviderID != current {
		t.Fatal("failed update changed settings")
	}
	info, err := os.Stat(filepath.Join(s.config.StateDir, "console-provider-"+current+".json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credentials are not private", err)
	}
}

func TestLegacyOIDCCredentialFileSurvivesUpgrade(t *testing.T) {
	s, p, _ := testConsole(t)
	state := mustConsoleState(t, s)
	legacy, _ := json.Marshal(providerCredentials{Issuer: p.server.URL, ClientID: "console-test", ClientSecret: "test-secret"})
	if err := os.WriteFile(filepath.Join(s.config.StateDir, "console-provider-"+state.ProviderID+".json"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(s.store, s.config)
	if err != nil {
		t.Fatal(err)
	}
	restarted.httpClient = s.httpClient
	b := newBrowser(t, restarted)
	if dest := b.login(p); dest != "/" {
		t.Fatal(dest)
	}
}

func TestDirectSocialSetupAndStableIdentity(t *testing.T) {
	for _, owner := range []string{"github", "google"} {
		t.Run(owner, func(t *testing.T) {
			s, _, gh, b, csrf, settings := socialConsole(t)
			response := b.request("POST", "/v1/console/setup/provider", settings, csrf, nil)
			saved := decodeTest[map[string]any](t, response, 200)
			if strings.Contains(response.Body.String(), "test-secret") || strings.Contains(response.Body.String(), "github-secret") {
				t.Fatal("credentials exposed")
			}
			if len(saved["providers"].([]any)) != 2 {
				t.Fatal("missing choices")
			}
			restarted, err := New(s.store, s.config)
			if err != nil {
				t.Fatal(err)
			}
			restarted.httpClient = s.httpClient
			if _, err = restarted.getProvider(context.Background(), mustConsoleState(t, s).ProviderID, "github"); err != nil {
				t.Fatal(err)
			}
			callback := startSocial(t, b, owner, csrf, true)
			if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/" {
				t.Fatal(dest)
			}
			identity := b.identity()
			if identity["role"] != "Admin" {
				t.Fatal(identity)
			}
			active := decodeTest[map[string]any](t, b.request("GET", "/v1/console/auth/status", nil, "", nil), 200)
			if len(active["providers"].([]any)) != 2 {
				t.Fatal(active)
			}
			if w := b.request("POST", "/v1/console/setup/provider", settings, csrf, nil); w.Code != 403 {
				t.Fatal("setup stayed open")
			}
			other := "google"
			if owner == "google" {
				other = "github"
			}
			visitor := newBrowser(t, s)
			callback = startSocial(t, visitor, other, visitor.pre(), false)
			if dest := visitor.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/login?reason=account_pending" {
				t.Fatal("another identity acquired authority", dest)
			}
			if visitor.request("GET", "/v1/me", nil, "", nil).Code != 401 {
				t.Fatal("pending identity has session")
			}
			gh.mu.Lock()
			gh.login = "renamed-owner"
			gh.mu.Unlock()
			returning := newBrowser(t, restarted)
			callback = startSocial(t, returning, owner, returning.pre(), false)
			if dest := returning.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/" {
				t.Fatal(dest)
			}
			if returning.identity()["principal_id"] != identity["principal_id"] {
				t.Fatal("stable provider identity changed")
			}
		})
	}
}

func TestGitHubFailuresCannotBindOrReplay(t *testing.T) {
	for _, mode := range []string{"exchange-error", "profile-error", "profile-redirect", "missing-id", "organization", "callback-mixup", "state", "pkce", "replay"} {
		t.Run(mode, func(t *testing.T) {
			s, _, gh, b, csrf, settings := socialConsole(t)
			settings.Providers = settings.Providers[1:]
			decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/provider", settings, csrf, nil), 200)
			gh.mu.Lock()
			gh.mode = mode
			gh.mu.Unlock()
			callback := startSocial(t, b, "github", csrf, true)
			switch mode {
			case "callback-mixup":
				callback = strings.Replace(callback, "/callback/github", "/callback/google", 1)
			case "state":
				callback += "&state=another-state"
			case "pkce":
				s.mu.Lock()
				for key, f := range s.flows {
					f.Verifier = "wrong"
					s.flows[key] = f
				}
				s.mu.Unlock()
			case "replay":
				if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/" {
					t.Fatal(dest)
				}
			}
			if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/login?reason=oidc_callback_invalid" {
				t.Fatal(dest)
			}
			if mode != "replay" {
				if mustConsoleState(t, s).Initialized {
					t.Fatal("failure created owner")
				}
				var count int
				if err := s.store.DB.QueryRow("SELECT count(*) FROM console_users").Scan(&count); err != nil || count != 0 {
					t.Fatal("failure persisted identity", count, err)
				}
			}
			if mode == "callback-mixup" {
				gh.mu.Lock()
				exchanges := gh.exchanges
				gh.mu.Unlock()
				if exchanges != 0 {
					t.Fatal("wrong callback redeemed a code")
				}
			}
		})
	}
}

type githubFixture struct {
	server      *httptest.Server
	mu          sync.Mutex
	grants      map[string]testGrant
	tokens      map[string]string
	mode, login string
	exchanges   int
}

func newGitHubFixture(t *testing.T) *githubFixture {
	g := &githubFixture{grants: map[string]testGrant{}, tokens: map[string]string{}, login: "original-owner"}
	g.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		g.mu.Lock()
		defer g.mu.Unlock()
		switch r.URL.Path {
		case "/login/oauth/authorize":
			q := r.URL.Query()
			if q.Get("client_id") != "github-test" || q.Get("response_type") != "code" || q.Get("scope") != "read:user" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") != "" || q.Get("redirect_uri") != "https://console.example/v1/console/auth/callback/github" {
				http.Error(w, "incorrect GitHub authorization request", 400)
				return
			}
			code := rand.Text()
			g.grants[code] = testGrant{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), mode: g.mode}
			callback, _ := url.Parse(q.Get("redirect_uri"))
			callback.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
			http.Redirect(w, r, callback.String(), 303)
		case "/login/oauth/access_token":
			_ = r.ParseForm()
			g.exchanges++
			grant, ok := g.grants[r.Form.Get("code")]
			delete(g.grants, r.Form.Get("code"))
			digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || r.Form.Get("client_id") != "github-test" || r.Form.Get("client_secret") != "github-secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != grant.redirect || base64.RawURLEncoding.EncodeToString(digest[:]) != grant.challenge {
				http.Error(w, "incorrect GitHub code exchange", 400)
				return
			}
			if grant.mode == "exchange-error" {
				http.Error(w, "private provider failure", 401)
				return
			}
			token := rand.Text()
			g.tokens[token] = grant.mode
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token, "token_type": "bearer", "scope": "read:user"})
		case "/user":
			mode, ok := g.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok || r.Header.Get("Accept") != "application/vnd.github+json" {
				http.Error(w, "not authorized", 401)
				return
			}
			switch mode {
			case "profile-error":
				http.Error(w, "profile unavailable", 503)
			case "profile-redirect":
				http.Redirect(w, r, g.server.URL+"/wrong", 302)
			case "missing-id":
				_, _ = w.Write([]byte(`{"login":"owner","name":"Owner","type":"User"}`))
			case "organization":
				_, _ = w.Write([]byte(`{"id":42,"login":"owner","type":"Organization"}`))
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": g.login, "name": "Account owner", "type": "User"})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.server.Close)
	return g
}
