package console

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/api"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	jose "github.com/go-jose/go-jose/v4"
)

// A TLS test IdP performs code + PKCE exchange and signs real ID tokens. Only
// the upstream identity provider is simulated; Console/SQLite/Fleet are real.
type testGrant struct{ nonce, challenge, redirect, subject, mode string }
type testProvider struct {
	server        *httptest.Server
	mu            sync.Mutex
	grants        map[string]testGrant
	signer        jose.Signer
	subject, mode string
	redirectURI   string
	issuer        string
}

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	p := &testProvider{grants: map[string]testGrant{}, signer: signer, subject: "owner", redirectURI: "https://console.example/v1/console/auth/callback"}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		issuer := p.server.URL
		if p.issuer != "" {
			issuer = p.issuer
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES256"}, "code_challenge_methods_supported": []string{"S256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "ES256", Use: "sig"}}})
		case "/authorize":
			q := r.URL.Query()
			if q.Get("client_id") != "console-test" || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("redirect_uri") != p.redirectURI {
				http.Error(w, "bad auth request", 400)
				return
			}
			code := rand.Text()
			p.mu.Lock()
			p.grants[code] = testGrant{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), p.subject, p.mode}
			p.mu.Unlock()
			callback, _ := url.Parse(q.Get("redirect_uri"))
			callback.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {issuer}}.Encode()
			http.Redirect(w, r, callback.String(), 303)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			client, secret, ok := r.BasicAuth()
			if !ok {
				client = r.Form.Get("client_id")
				secret = r.Form.Get("client_secret")
			}
			p.mu.Lock()
			grant, exists := p.grants[r.Form.Get("code")]
			delete(p.grants, r.Form.Get("code"))
			p.mu.Unlock()
			digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !exists || client != "console-test" || secret != "test-secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != grant.redirect || base64.RawURLEncoding.EncodeToString(digest[:]) != grant.challenge {
				http.Error(w, "invalid grant", 400)
				return
			}
			claims := map[string]any{"iss": issuer, "sub": grant.subject, "aud": "console-test", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "nonce": grant.nonce, "name": "Account " + grant.subject}
			switch grant.mode {
			case "nonce":
				claims["nonce"] = "wrong"
			case "aud":
				claims["aud"] = "other"
			case "issuer":
				claims["iss"] = "https://other.example"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "azp":
				claims["aud"] = []string{"console-test", "other"}
				claims["azp"] = "other"
			}
			body, _ := json.Marshal(claims)
			signed, err := p.signer.Sign(body)
			if err != nil {
				t.Error(err)
				return
			}
			token, err := signed.CompactSerialize()
			if err != nil {
				t.Error(err)
				return
			}
			if grant.mode == "signature" {
				parts := strings.Split(token, ".")
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sig[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(sig)
				token = strings.Join(parts, ".")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "unused-test-access-token", "token_type": "Bearer", "id_token": token})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}

type testBrowser struct {
	t       *testing.T
	s       *Server
	handler http.Handler
	jar     http.CookieJar
}

func newBrowser(t *testing.T, s *Server) *testBrowser {
	jar, _ := cookiejar.New(nil)
	return &testBrowser{t, s, s.Handler(), jar}
}
func (b *testBrowser) request(method, path string, body any, csrfToken string, headers map[string]string) *httptest.ResponseRecorder {
	b.t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			b.t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, b.s.config.Origin+path, bytes.NewReader(data))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.RemoteAddr = "127.0.0.1:1234"
	for _, cookie := range b.jar.Cookies(r.URL) {
		r.AddCookie(cookie)
	}
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", b.s.config.Origin)
		r.Header.Set("X-CSRF-Token", csrfToken)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	b.jar.SetCookies(r.URL, w.Result().Cookies())
	return w
}
func decodeTest[T any](t *testing.T, w *httptest.ResponseRecorder, status int) T {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP %d, expected %d: %s", w.Code, status, w.Body.String())
	}
	var out T
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func (b *testBrowser) pre() string {
	v := decodeTest[map[string]any](b.t, b.request("GET", "/v1/console/auth/status", nil, "", nil), 200)
	return v["csrf_token"].(string)
}
func (b *testBrowser) identity() map[string]any {
	return decodeTest[map[string]any](b.t, b.request("GET", "/v1/me", nil, "", nil), 200)
}
func (b *testBrowser) start(p *testProvider, csrfToken string, setup bool) string {
	b.t.Helper()
	path := "/v1/console/auth/login"
	if setup {
		path = "/v1/console/setup/bind"
	}
	decodeTest[map[string]any](b.t, b.request("POST", path, struct{}{}, csrfToken, nil), 200)
	w := b.request("GET", "/v1/console/auth/redirect", nil, "", nil)
	if w.Code != 303 {
		b.t.Fatal("no redirect", w.Code, w.Body.String())
	}
	client := p.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(w.Header().Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 303 {
		b.t.Fatal("IdP rejected authorization")
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	return u.RequestURI()
}
func (b *testBrowser) login(p *testProvider) string {
	callback := b.start(p, b.pre(), false)
	w := b.request("GET", callback, nil, "", nil)
	if w.Code != 303 {
		b.t.Fatal("callback did not redirect", w.Code)
	}
	return w.Header().Get("Location")
}
func testConsole(t *testing.T) (*Server, *testProvider, *testBrowser) {
	t.Helper()
	s, p, b, csrfToken := setupConsole(t)
	callback := b.start(p, csrfToken, true)
	w := b.request("GET", callback, nil, "", nil)
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatal("setup failed", w.Code, w.Header().Get("Location"))
	}
	return s, p, b
}
func setupConsole(t *testing.T) (*Server, *testProvider, *testBrowser, string) {
	t.Helper()
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
	p := newTestProvider(t)
	client := p.server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Transport = boundedTransport{client.Transport}
	s.httpClient = client
	b := newBrowser(t, s)
	secret, err := store.IssueConsoleBootstrap(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	setup := decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/prove", map[string]string{"secret": secret}, b.pre(), nil), 200)
	csrfToken := setup["csrf_token"].(string)
	decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/provider", providerCredentials{Issuer: p.server.URL, ClientID: "console-test", ClientSecret: "test-secret"}, csrfToken, nil), 200)
	return s, p, b, csrfToken
}

func TestConsoleFailedFirstBindingDoesNotCreateOwner(t *testing.T) {
	s, p, b, csrfToken := setupConsole(t)
	p.mu.Lock()
	p.mode = "signature"
	p.mu.Unlock()
	callback := b.start(p, csrfToken, true)
	if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/login?reason=oidc_callback_invalid" {
		t.Fatal(dest)
	}
	state, err := s.store.ConsoleState(context.Background())
	if err != nil || state.Initialized {
		t.Fatal("invalid signature activated Console", err)
	}
	var count int
	if err = s.store.DB.QueryRow("SELECT count(*) FROM console_users").Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid signature created user", count, err)
	}
	if w := b.request("GET", "/v1/console/admin/users", nil, "", nil); w.Code != 401 {
		t.Fatal("setup acquired management authority")
	}
}

func TestConsoleRecoversMissingProviderCredentials(t *testing.T) {
	s, p, _ := testConsole(t)
	ctx := context.Background()
	state, err := s.store.ConsoleState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(s.config.StateDir, "console-provider-"+state.ProviderID+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err = New(s.store, s.config); err == nil {
		t.Fatal("missing active credentials accepted")
	}
	secret, err := s.store.IssueConsoleBootstrap(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := New(s.store, s.config)
	if err != nil {
		t.Fatal("local recovery cannot repair missing provider", err)
	}
	recovered.httpClient = s.httpClient
	b := newBrowser(t, recovered)
	setup := decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/prove", map[string]string{"secret": secret}, b.pre(), nil), 200)
	if setup["step"] != "provider" || setup["issuer"] != "" {
		t.Fatal(setup)
	}
	csrfToken := setup["csrf_token"].(string)
	decodeTest[map[string]any](t, b.request("POST", "/v1/console/setup/provider", providerCredentials{Issuer: p.server.URL, ClientID: "console-test", ClientSecret: "test-secret"}, csrfToken, nil), 200)
	p.mu.Lock()
	p.subject = "recovered-owner"
	p.mu.Unlock()
	callback := b.start(p, csrfToken, true)
	if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/" {
		t.Fatal(dest)
	}
	if b.identity()["role"] != "Admin" {
		t.Fatal("recovered account is not Admin")
	}
}

func TestConsoleOIDCAndAuthorityBoundary(t *testing.T) {
	s, p, admin := testConsole(t)
	identity := admin.identity()
	if identity["role"] != "Admin" {
		t.Fatal(identity)
	}
	csrfToken := identity["csrf_token"].(string)
	for _, name := range []string{sessionCookie} {
		u, _ := url.Parse(s.config.Origin)
		found := false
		for _, c := range admin.jar.Cookies(u) {
			if c.Name == name {
				found = true
			}
		}
		if !found {
			t.Fatal("missing session cookie")
		}
	}
	for _, tc := range []struct {
		name    string
		headers map[string]string
		csrf    string
		status  int
	}{
		{"no csrf", nil, "", 403}, {"wrong csrf", nil, "wrong", 403}, {"wrong origin", map[string]string{"Origin": "https://evil.example"}, csrfToken, 403}, {"no origin", map[string]string{"Origin": ""}, csrfToken, 403}, {"bearer never authenticates", map[string]string{"Authorization": "Bearer cli-secret"}, csrfToken, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := admin.request("POST", "/v1/console/admin/enrollment-tokens", map[string]int{"ttl_seconds": 60}, tc.csrf, tc.headers)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	guest := newBrowser(t, s)
	for _, path := range []string{"/v1/console/admin/tasks", "/v1/console/admin/agents", "/v1/console/admin/audit", "/v1/console/admin/users"} {
		if w := guest.request("GET", path, nil, "", nil); w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	if w := guest.request("GET", "/v1/console/public/summary", nil, "", nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, path := range []string{"/v1/agent/poll", "/v1/enroll", "/v1/tasks"} {
		if w := guest.request("GET", path, nil, "", nil); w.Code != 404 {
			t.Fatal("Fleet route on Console", path, w.Code)
		}
	}
	if w := admin.request("GET", "/v1/console/setup", nil, "", nil); w.Code != 403 {
		t.Fatal("ACTIVE setup open")
	}
	// A Console cookie cannot authorize the existing Fleet API.
	r := httptest.NewRequest("GET", "https://fleet.example/v1/nodes", nil)
	r.TLS = &tls.ConnectionState{}
	u, _ := url.Parse(s.config.Origin)
	for _, c := range admin.jar.Cookies(u) {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	(&api.Server{Store: s.store}).Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("Console credential authenticated Fleet", w.Code)
	}
	oldCookies := admin.jar.Cookies(u)
	decodeTest[map[string]any](t, admin.request("POST", "/v1/console/auth/logout", struct{}{}, csrfToken, nil), 200)
	admin.jar.SetCookies(u, oldCookies)
	if w := admin.request("GET", "/v1/me", nil, "", nil); w.Code != 401 {
		t.Fatal("logout left session valid")
	}
	if dest := admin.login(p); dest != "/" {
		t.Fatal(dest)
	}
	restarted, err := New(s.store, s.config)
	if err != nil {
		t.Fatal(err)
	}
	admin.handler = restarted.Handler()
	if w := admin.request("GET", "/v1/me", nil, "", nil); w.Code != 401 {
		t.Fatal("memory session survived restart")
	}
	state, err := s.store.ConsoleState(context.Background())
	if err != nil || !state.Initialized {
		t.Fatal("activation did not persist", err)
	}
}

func TestConsoleRejectsOIDCReplayAndInvalidClaims(t *testing.T) {
	for _, mode := range []string{"nonce", "aud", "issuer", "expired", "azp", "signature", "state", "replay"} {
		t.Run(mode, func(t *testing.T) {
			s, p, _ := testConsole(t)
			b := newBrowser(t, s)
			p.mu.Lock()
			p.mode = mode
			p.mu.Unlock()
			path := b.start(p, b.pre(), false)
			if mode == "state" {
				u, _ := url.Parse(path)
				q := u.Query()
				q.Set("state", "attacker-state")
				u.RawQuery = q.Encode()
				path = u.String()
			}
			w := b.request("GET", path, nil, "", nil)
			if mode == "replay" {
				if w.Header().Get("Location") != "/" {
					t.Fatal("valid callback rejected")
				}
				w = b.request("GET", path, nil, "", nil)
			}
			if w.Header().Get("Location") != "/login?reason=oidc_callback_invalid" {
				t.Fatal("invalid callback accepted", mode, w.Code, w.Header().Get("Location"))
			}
			if mode != "replay" {
				if w = b.request("GET", "/v1/me", nil, "", nil); w.Code != 401 {
					t.Fatal("failed OIDC granted session")
				}
			}
		})
	}
}

func TestConsoleRealManagementAndPublicProjection(t *testing.T) {
	s, p, admin := testConsole(t)
	ctx := context.Background()
	me := admin.identity()
	csrfToken := me["csrf_token"].(string)
	token := decodeTest[struct {
		Token   string `json:"token"`
		Expires int64  `json:"expires_at"`
	}](t, admin.request("POST", "/v1/console/admin/enrollment-tokens", map[string]int{"ttl_seconds": 60}, csrfToken, nil), 200)
	root := filepath.Join(t.TempDir(), "pki")
	if err := enrollment.Initialize(root, []string{"localhost"}); err != nil {
		t.Fatal(err)
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
	enrolled, err := (enrollment.Service{Store: s.store, Issuer: issuer}).Enroll(ctx, protocol.EnrollmentRequest{Token: token.Token, Hostname: "private-10.0.0.7", CSR: csr}, protocol.AgentMetadata{ProtocolVersion: protocol.Version, AgentVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(enrolled.Certificate))
	if block == nil {
		t.Fatal("missing leaf")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pendingAgents := decodeTest[page[managedAgent]](t, admin.request("GET", "/v1/console/admin/agents", nil, "", nil), 200)
	if len(pendingAgents.Items) != 1 {
		t.Fatal("enrolled Agent must remain available to administrators")
	}
	beforeHeartbeat := newBrowser(t, s)
	if pending := decodeTest[publicSummary](t, beforeHeartbeat.request("GET", "/v1/console/public/summary", nil, "", nil), 200); len(pending.Nodes) != 0 {
		t.Fatal("unseen Agent appeared in public overview")
	}
	decodeTest[map[string]string](t, beforeHeartbeat.request("GET", "/v1/console/public/nodes/"+pendingAgents.Items[0].PublicID+"/history?range=1h", nil, "", nil), 404)
	if err = s.store.Heartbeat(ctx, cert, "private-10.0.0.7", protocol.AgentMetadata{ProtocolVersion: protocol.Version, AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	agents := decodeTest[page[managedAgent]](t, admin.request("GET", "/v1/console/admin/agents?q=10.0.0.7", nil, "", nil), 200)
	if len(agents.Items) != 1 {
		t.Fatal(agents)
	}
	agent := agents.Items[0]
	create := func(kind protocol.TaskType) managedTask {
		return decodeTest[managedTask](t, admin.request("POST", "/v1/console/admin/tasks", protocol.TaskRequest{NodeID: enrolled.NodeID, Type: kind, Params: json.RawMessage(`{}`), TTLSeconds: 300, ExecutionTimeoutMS: 10000}, csrfToken, nil), 200)
	}
	infoTask := create(protocol.SystemInfo)
	assignment, err := s.store.Poll(ctx, cert)
	if err != nil || assignment == nil || assignment.ID != infoTask.ID {
		t.Fatal(assignment, err)
	}
	if err = s.store.Running(ctx, cert, infoTask.ID); err != nil {
		t.Fatal(err)
	}
	info := protocol.SystemInformation{Available: true, OS: "Ubuntu 24.04 LTS", Architecture: "x86_64", Hostname: "private-10.0.0.7", Kernel: "6.8.0-private", BootTime: time.Now().Add(-time.Hour).Unix()}
	payload, _ := json.Marshal(info)
	if err = s.store.SubmitResult(ctx, cert, protocol.Result{TaskID: infoTask.ID, NodeID: enrolled.NodeID, Status: protocol.Succeeded, Payload: payload, CompletedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	metricsTask := create(protocol.SystemMetrics)
	assignment, err = s.store.Poll(ctx, cert)
	if err != nil || assignment == nil || assignment.ID != metricsTask.ID {
		t.Fatal(assignment, err)
	}
	if err = s.store.Running(ctx, cert, metricsTask.ID); err != nil {
		t.Fatal(err)
	}
	metrics := protocol.SystemMeasurements{CPU: protocol.CPUStats{Available: true, BusyPercent: 25, WindowMS: 1000}, Memory: protocol.MemoryStats{Available: true, TotalBytes: 1000, AvailableBytes: 400}, Disks: []protocol.DiskStats{{Path: "/private/data", Available: true, TotalBytes: 2000, AvailableBytes: 1000}}, Networks: []protocol.NetworkStats{{Interface: "private0", Available: true, RXBytes: 100, TXBytes: 200}}}
	payload, _ = json.Marshal(metrics)
	if err = s.store.SubmitResult(ctx, cert, protocol.Result{TaskID: metricsTask.ID, NodeID: enrolled.NodeID, Status: protocol.Succeeded, Payload: payload, CompletedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	detail := decodeTest[taskDetail](t, admin.request("GET", "/v1/console/admin/tasks/"+metricsTask.ID, nil, "", nil), 200)
	if detail.Result == nil || detail.Task.ExecutionAuthorizedAt == nil || detail.Task.Status != protocol.Succeeded {
		t.Fatal(detail)
	}
	guest := newBrowser(t, s)
	response := guest.request("GET", "/v1/console/public/summary", nil, "", nil)
	summary := decodeTest[publicSummary](t, response, 200)
	if len(summary.Nodes) != 1 || *summary.Nodes[0].Resources.CPU != 25 || summary.Nodes[0].Traffic.Inbound != nil || *summary.Nodes[0].System.OS != "Ubuntu 24.04" {
		t.Fatal(summary)
	}
	for _, secret := range []string{"10.0.0.7", "private-", "private0", "/private/data", enrolled.NodeID, metricsTask.ID, "certificate", "parameters", "networks"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("public projection leak", secret)
		}
	}
	history := decodeTest[publicHistory](t, guest.request("GET", "/v1/console/public/nodes/"+agent.PublicID+"/history?range=1h", nil, "", nil), 200)
	if len(history.Points) != 1 || *history.Points[0].Memory != 60 || history.Points[0].Inbound != nil {
		t.Fatal(history)
	}
	// Pending identities receive no session until an administrator approves them.
	p.mu.Lock()
	p.subject = "viewer"
	p.mu.Unlock()
	viewer := newBrowser(t, s)
	if dest := viewer.login(p); dest != "/login?reason=account_pending" {
		t.Fatal(dest)
	}
	users := decodeTest[page[database.ConsoleUser]](t, admin.request("GET", "/v1/console/admin/users?status=pending", nil, "", nil), 200)
	if len(users.Items) != 1 {
		t.Fatal(users)
	}
	user := users.Items[0]
	edit := map[string]any{"role": "User", "status": "active", "expected_version": user.Version, "confirm_subject": user.Subject}
	approved := decodeTest[database.ConsoleUser](t, admin.request("POST", "/v1/console/admin/users/"+user.ID, edit, csrfToken, nil), 200)
	if w := admin.request("POST", "/v1/console/admin/users/"+user.ID, edit, csrfToken, nil); w.Code != 409 {
		t.Fatal("stale edit succeeded")
	}
	if dest := viewer.login(p); dest != "/" {
		t.Fatal(dest)
	}
	vme := viewer.identity()
	if vme["role"] != "User" {
		t.Fatal(vme)
	}
	for _, path := range []string{"tasks", "agents", "audit", "users"} {
		if w := viewer.request("GET", "/v1/console/admin/"+path, nil, "", nil); w.Code != 403 {
			t.Fatal("User read management", path, w.Code)
		}
	}
	if w := viewer.request("POST", "/v1/console/admin/enrollment-tokens", map[string]int{"ttl_seconds": 60}, vme["csrf_token"].(string), nil); w.Code != 403 {
		t.Fatal("User performed write")
	}
	decodeTest[map[string]any](t, admin.request("POST", "/v1/console/admin/users/"+user.ID+"/revoke-sessions", struct{}{}, csrfToken, nil), 200)
	if w := viewer.request("GET", "/v1/me", nil, "", nil); w.Code != 401 {
		t.Fatal("revoked session accepted")
	}
	edit["role"] = "Admin"
	edit["expected_version"] = approved.Version + 1
	decodeTest[database.ConsoleUser](t, admin.request("POST", "/v1/console/admin/users/"+user.ID, edit, csrfToken, nil), 200)
	if dest := viewer.login(p); dest != "/" {
		t.Fatal(dest)
	}
	if promoted := viewer.identity(); promoted["role"] != "Admin" {
		t.Fatal("promotion not effective", promoted)
	}
	queued := create(protocol.SystemInfo)
	decodeTest[managedAgent](t, admin.request("POST", "/v1/console/admin/agents/"+agent.NodeID+"/disable", map[string]string{"confirm_node_id": agent.NodeID}, csrfToken, nil), 200)
	failed := decodeTest[taskDetail](t, admin.request("GET", "/v1/console/admin/tasks/"+queued.ID, nil, "", nil), 200)
	if failed.Task.Status != protocol.Failed {
		t.Fatal(failed)
	}
	if _, err = s.store.Poll(ctx, cert); err != database.ErrUnauthorized {
		t.Fatal("disabled agent still authorized", err)
	}
	w := admin.request("POST", "/v1/console/admin/tasks", protocol.TaskRequest{NodeID: agent.NodeID, Type: protocol.SystemInfo, Params: json.RawMessage(`{}`), TTLSeconds: 300, ExecutionTimeoutMS: 1000}, csrfToken, nil)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	audit := decodeTest[page[auditEvent]](t, admin.request("GET", "/v1/console/admin/audit?node_id="+agent.NodeID, nil, "", nil), 200)
	if audit.Total < 5 {
		t.Fatal(audit)
	}
	if strings.Contains(admin.request("GET", "/v1/console/admin/audit", nil, "", nil).Body.String(), token.Token) {
		t.Fatal("token leaked into audit")
	}
	tasks := decodeTest[page[managedTask]](t, admin.request("GET", "/v1/console/admin/tasks?limit=1", nil, "", nil), 200)
	if tasks.Total != 3 || tasks.NextCursor == nil {
		t.Fatal("task page invalid", tasks)
	}
	next := decodeTest[page[managedTask]](t, admin.request("GET", "/v1/console/admin/tasks?limit=1&cursor="+url.QueryEscape(*tasks.NextCursor), nil, "", nil), 200)
	if len(next.Items) != 1 || next.Items[0].ID == tasks.Items[0].ID {
		t.Fatal("pagination duplicated a task")
	}
	if w := admin.request("GET", "/v1/console/admin/tasks?status=FAILED&cursor="+url.QueryEscape(*tasks.NextCursor), nil, "", nil); w.Code != 400 {
		t.Fatal("cursor allowed changed filter")
	}
	if output := os.Getenv("ARGUS_CONSOLE_CONTRACT_FILE"); output != "" {
		golden := map[string]any{"identity": me, "summary": summary, "history": history, "agents": agents, "tasks": tasks, "task": detail, "users": users, "audit": audit, "enrollment": token}
		data, err := json.MarshalIndent(golden, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConsoleSessionCookieFlagsAndExpiry(t *testing.T) {
	s, p, _ := testConsole(t)
	b := newBrowser(t, s)
	path := b.start(p, b.pre(), false)
	w := b.request("GET", path, nil, "", nil)
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			found = true
			if !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" || c.SameSite != http.SameSiteStrictMode {
				t.Fatal(c)
			}
		}
	}
	if !found {
		t.Fatal("no session")
	}
	now := time.Now()
	s.now = func() time.Time { return now.Add(31 * time.Minute) }
	if w := b.request("GET", "/v1/me", nil, "", nil); w.Code != 401 {
		t.Fatal("idle expiry failed")
	}
}
