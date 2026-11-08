package console

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type providerCredentials struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Kind         string `json:"kind,omitempty"`
}
type providerSettings struct {
	Providers []providerCredentials `json:"providers"`
}

// Accept the original single-OIDC configuration as well as provider sets.
type providerInput struct {
	providerCredentials
	Providers []json.RawMessage `json:"providers"`
}

const googleIssuer = "https://accounts.google.com"

// Preserve the existing GitHub account namespace across upgrades. It is not
// GitHub's RFC 9207 authorization-response issuer.
const githubIssuer = "https://github.com"

// Published at https://github.com/login/oauth/.well-known/openid-configuration.
const githubAuthorizationIssuer = "https://github.com/login/oauth"

func callbackPath(kind string) string {
	if kind == "google" || kind == "github" {
		return "/v1/console/auth/callback/" + kind
	}
	return "/v1/console/auth/callback"
}

func providerLabel(c providerCredentials) string {
	switch c.Kind {
	case "google":
		return "Google"
	case "github":
		return "GitHub"
	default:
		u, _ := url.Parse(c.Issuer)
		return u.Host
	}
}

func normalizeProviders(input providerInput) ([]providerCredentials, error) {
	var items []providerCredentials
	if input.Providers == nil {
		items = []providerCredentials{input.providerCredentials}
	} else if input.providerCredentials != (providerCredentials{}) {
		return nil, errors.New("mixed provider formats")
	} else {
		for _, raw := range input.Providers {
			var c providerCredentials
			if err := strictjson.Decode(raw, &c, 8192, "kind", "issuer", "client_id", "client_secret"); err != nil {
				return nil, err
			}
			items = append(items, c)
		}
	}
	if len(items) < 1 || len(items) > 3 {
		return nil, errors.New("choose one to three login providers")
	}
	seen := map[string]bool{}
	for i := range items {
		c := &items[i]
		if c.Kind == "" {
			c.Kind = "oidc"
		}
		if seen[c.Kind] {
			return nil, errors.New("duplicate login provider")
		}
		seen[c.Kind] = true
		switch c.Kind {
		case "google", "github":
			issuer := googleIssuer
			if c.Kind == "github" {
				issuer = githubIssuer
			}
			if c.Issuer != "" && c.Issuer != issuer {
				return nil, errors.New("social provider endpoint cannot be changed")
			}
			c.Issuer = issuer
		case "oidc":
			// The issuer is explicitly supplied for custom OIDC providers.
		default:
			return nil, errors.New("unsupported login provider")
		}
		u, err := url.Parse(c.Issuer)
		if err != nil || !secureEndpoint(c.Issuer) || u.RawQuery != "" || c.ClientID == "" || !protocol.CleanText(c.ClientID, 512) || !protocol.CleanText(c.ClientSecret, 4096) {
			return nil, errors.New("invalid provider settings")
		}
	}
	return items, nil
}

type provider struct {
	ID          string
	Credentials providerCredentials
	OAuth       oauth2.Config
	Verifier    *oidc.IDTokenVerifier
}
type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, errors.New("OIDC requires HTTPS")
	}
	if r.URL.Host == "github.com" && r.URL.Path == "/login/oauth/access_token" || r.URL.Host == "api.github.com" && r.URL.Path == "/user" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", "ARGUS-Console")
		if r.URL.Host == "github.com" {
			r.Header.Set("Accept", "application/json")
		}
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(b) > 1024*1024 {
		return nil, errors.New("OIDC response unavailable or exceeds limit")
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	return resp, nil
}
func oidcHTTPClient() *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	base.ResponseHeaderTimeout = 8 * time.Second
	base.MaxResponseHeaderBytes = 16384
	base.MaxConnsPerHost = 4
	return &http.Client{Timeout: 10 * time.Second, Transport: boundedTransport{base}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OIDC HTTP redirects are not accepted") }}
}
func secureEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" && len(raw) <= 2048
}
func (s *Server) readProvider(id string) ([]providerCredentials, error) {
	var input providerInput
	if !identity.Valid(id) {
		return nil, errors.New("invalid provider ID")
	}
	b, err := localfile.Read(filepath.Join(s.config.StateDir, "console-provider-"+id+".json"), 32768, true)
	if err == nil {
		err = strictjson.Decode(b, &input, 32768, "providers")
		if err != nil {
			err = strictjson.Decode(b, &input, 32768, "issuer", "client_id", "client_secret")
		}
	}
	if err != nil {
		return nil, err
	}
	return normalizeProviders(input)
}
func (s *Server) discover(ctx context.Context, id string, c providerCredentials) (*provider, error) {
	items, err := normalizeProviders(providerInput{providerCredentials: c})
	if err != nil {
		return nil, err
	}
	c = items[0]
	if c.Kind != "oidc" && c.ClientSecret == "" {
		return nil, errors.New("social login requires an application secret")
	}
	if c.Kind == "github" {
		return &provider{ID: id, Credentials: c, OAuth: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret,
			Endpoint:    oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams},
			RedirectURL: s.config.Origin + callbackPath(c.Kind), Scopes: []string{"read:user"},
		}}, nil
	}
	ctx = oidc.ClientContext(ctx, s.httpClient)
	p, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if err = p.Claims(&metadata); err != nil {
		return nil, err
	}
	endpoint := p.Endpoint()
	if !secureEndpoint(endpoint.AuthURL) || !secureEndpoint(endpoint.TokenURL) || !secureEndpoint(metadata.JWKS) {
		return nil, errors.New("invalid OIDC endpoints")
	}
	if c.Kind == "google" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	return &provider{ID: id, Credentials: c, OAuth: oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: endpoint, RedirectURL: s.config.Origin + callbackPath(c.Kind), Scopes: []string{oidc.ScopeOpenID, "profile"}}, Verifier: p.VerifierContext(oidc.ClientContext(context.Background(), s.httpClient), &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256}, Now: s.now})}, nil
}
func (s *Server) getProvider(ctx context.Context, id, kind string) (*provider, error) {
	s.providerMu.Lock()
	defer s.providerMu.Unlock()
	if p := s.cachedProviders[kind]; p != nil && p.ID == id {
		return p, nil
	}
	items, err := s.readProvider(id)
	if err != nil {
		return nil, err
	}
	for _, c := range items {
		if c.Kind != kind && !(kind == "" && len(items) == 1) {
			continue
		}
		p, err := s.discover(ctx, id, c)
		if err == nil {
			if s.cachedProviders == nil {
				s.cachedProviders = map[string]*provider{}
			}
			s.cachedProviders[c.Kind] = p
		}
		return p, err
	}
	return nil, errors.New("login provider is not configured")
}
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.ConsoleState(r.Context())
	if err != nil {
		storeProblem(w, err)
		return
	}
	v, ok := s.lookup(r, preCookie, "pre")
	if !ok {
		v, ok = s.putSession(w, r, preCookie, session{Kind: "pre", Expires: s.now().Add(10 * time.Minute)})
		if !ok {
			problem(w, 503, "service_unavailable")
			return
		}
	}
	status := "UNINITIALIZED"
	if state.Initialized {
		status = "ACTIVE"
	}
	if state.SetupOpen(s.now().Unix()) {
		status = "SETUP_PENDING"
	}
	var providerName *string
	providers := []map[string]string{}
	if state.ProviderID != "" {
		items, e := s.readProvider(state.ProviderID)
		if e != nil {
			if !state.SetupOpen(s.now().Unix()) {
				problem(w, 503, "service_unavailable")
				return
			}
		}
		for _, c := range items {
			name := providerLabel(c)
			if providerName == nil {
				providerName = &name
			}
			providers = append(providers, map[string]string{"kind": c.Kind, "name": name})
		}
	}
	tokenEnabled, err := s.store.ConsoleTokenAvailable(r.Context())
	if err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, map[string]any{"state": status, "provider_name": providerName, "providers": providers, "csrf_token": v.CSRF, "token_enabled": tokenEnabled})
}
func (s *Server) setupSession(w http.ResponseWriter, r *http.Request, write bool) (session, database.ConsoleState, bool) {
	state, err := s.store.ConsoleState(r.Context())
	if err != nil {
		storeProblem(w, err)
		return session{}, state, false
	}
	if state.Initialized && !state.Recovery {
		problem(w, 403, "setup_closed")
		return session{}, state, false
	}
	v, ok := s.lookup(r, setupCookie, "setup")
	if !ok || v.Generation != state.Generation || !state.SetupOpen(s.now().Unix()) {
		problem(w, 401, "session_expired")
		return v, state, false
	}
	if write && !csrf(r, v) {
		problem(w, 403, "csrf_invalid")
		return v, state, false
	}
	return v, state, true
}
func (s *Server) setupReply(w http.ResponseWriter, v session, state database.ConsoleState) {
	items := []providerCredentials{}
	step := "provider"
	if state.ProviderID != "" {
		var err error
		items, err = s.readProvider(state.ProviderID)
		if err == nil {
			step = "bind"
		}
	}
	providers := []map[string]string{}
	c := providerCredentials{}
	for _, item := range items {
		providers = append(providers, map[string]string{"kind": item.Kind, "name": providerLabel(item), "issuer": item.Issuer, "client_id": item.ClientID})
		if c.ClientID == "" {
			c = item
		}
	}
	callbacks := map[string]string{}
	for _, kind := range []string{"google", "github", "oidc"} {
		callbacks[kind] = s.config.Origin + callbackPath(kind)
	}
	reply(w, map[string]any{"step": step, "csrf_token": v.CSRF, "callback_uri": callbacks["oidc"], "issuer": c.Issuer, "client_id": c.ClientID, "providers": providers, "callback_uris": callbacks})
}
func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	v, state, ok := s.setupSession(w, r, false)
	if ok {
		s.setupReply(w, v, state)
	}
}
func (s *Server) prove(w http.ResponseWriter, r *http.Request) {
	v, ok := s.lookup(r, preCookie, "pre")
	if !ok || !csrf(r, v) {
		problem(w, 403, "csrf_invalid")
		return
	}
	var b struct {
		Secret string `json:"secret"`
	}
	if !decode(w, r, &b, "secret") {
		return
	}
	state, err := s.store.ProveConsoleBootstrap(r.Context(), strings.ToLower(b.Secret))
	if err != nil {
		storeProblem(w, err)
		return
	}
	v, ok = s.putSession(w, r, setupCookie, session{Kind: "setup", Generation: state.Generation, Expires: time.Unix(state.BootstrapExpires, 0)})
	if !ok {
		problem(w, 503, "service_unavailable")
		return
	}
	s.setupReply(w, v, state)
}
func (s *Server) configureProvider(w http.ResponseWriter, r *http.Request) {
	v, state, ok := s.setupSession(w, r, true)
	if !ok {
		return
	}
	s.saveProvider(w, r, v, state, false)
}
func (s *Server) saveProvider(w http.ResponseWriter, r *http.Request, v session, state database.ConsoleState, account bool) {
	var input providerInput
	if !decodeAlternatives(w, r, &input, []string{"providers"}, []string{"issuer", "client_id", "client_secret"}) {
		return
	}
	items, err := normalizeProviders(input)
	if err != nil {
		problem(w, 400, "invalid_request")
		return
	}
	previous, _ := s.readProvider(state.ProviderID)
	// A resumed setup may keep a saved secret, but only for the same provider,
	// issuer and client. Secrets are never returned to the browser.
	for i := range items {
		for _, old := range previous {
			if items[i].ClientSecret == "" && items[i].Kind == old.Kind && items[i].Issuer == old.Issuer && items[i].ClientID == old.ClientID {
				items[i].ClientSecret = old.ClientSecret
			}
		}
	}
	id := identity.RandomID()
	providers := map[string]*provider{}
	for _, c := range items {
		p, err := s.discover(r.Context(), id, c)
		if err != nil {
			problem(w, 503, "oidc_unavailable")
			return
		}
		providers[c.Kind] = p
	}
	path := filepath.Join(s.config.StateDir, "console-provider-"+id+".json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		problem(w, 503, "service_unavailable")
		return
	}
	err = json.NewEncoder(f).Encode(providerSettings{Providers: items})
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil && runtime.GOOS != "windows" {
		var d *os.File
		d, err = os.Open(s.config.StateDir)
		if err == nil {
			err = d.Sync()
			d.Close()
		}
	}
	if err == nil {
		if account {
			issuers := make([]string, 0, len(items))
			for _, p := range items {
				issuers = append(issuers, p.Issuer)
			}
			err = s.store.ConfigureConsoleProvider(r.Context(), v.Generation, state.ProviderID, id, issuers...)
		} else {
			err = s.store.SetConsoleProvider(r.Context(), v.Generation, id)
		}
	}
	if err != nil {
		_ = os.Remove(path)
		if errors.Is(err, database.ErrOAuthRequired) {
			problem(w, 409, "last_signin_method")
			return
		}
		storeProblem(w, err)
		return
	}
	s.providerMu.Lock()
	s.cachedProviders = providers
	s.providerMu.Unlock()
	state, err = s.store.ConsoleState(r.Context())
	if err != nil {
		storeProblem(w, err)
		return
	}
	s.setupReply(w, v, state)
}
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, setup bool) {
	var state database.ConsoleState
	if setup {
		_, st, ok := s.setupSession(w, r, true)
		if !ok {
			return
		}
		state = st
	} else {
		v, ok := s.lookup(r, preCookie, "pre")
		if !ok || !csrf(r, v) {
			problem(w, 403, "csrf_invalid")
			return
		}
		var err error
		state, err = s.store.ConsoleState(r.Context())
		if err != nil {
			storeProblem(w, err)
			return
		}
		if !state.Initialized || state.Recovery {
			problem(w, 403, "setup_closed")
			return
		}
	}
	s.startFlow(w, r, state, setup, session{})
}
func (s *Server) startFlow(w http.ResponseWriter, r *http.Request, state database.ConsoleState, setup bool, binding session) {
	var choice struct {
		Provider string `json:"provider"`
	}
	if !decodeAlternatives(w, r, &choice, []string{"provider"}, nil) {
		return
	}
	if choice.Provider != "" && choice.Provider != "google" && choice.Provider != "github" && choice.Provider != "oidc" {
		problem(w, 400, "invalid_request")
		return
	}
	p, err := s.getProvider(r.Context(), state.ProviderID, choice.Provider)
	if err != nil {
		problem(w, 503, "oidc_unavailable")
		return
	}
	stateToken, nonce, raw := identity.RandomID()+identity.RandomID(), identity.RandomID(), identity.RandomID()+identity.RandomID()
	verifier := oauth2.GenerateVerifier()
	expires := s.now().Add(5 * time.Minute)
	if setup && time.Unix(state.BootstrapExpires, 0).Before(expires) {
		expires = time.Unix(state.BootstrapExpires, 0)
	}
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if p.Credentials.Kind != "github" {
		options = append(options, oidc.Nonce(nonce))
	}
	authURL := p.OAuth.AuthCodeURL(stateToken, options...)
	s.mu.Lock()
	s.cleanLocked()
	if len(s.flows) >= 128 {
		s.mu.Unlock()
		problem(w, 503, "service_unavailable")
		return
	}
	delete(s.flows, database.TokenDigest(cookieValue(r, flowCookie)))
	s.flows[database.TokenDigest(raw)] = flow{StateDigest: database.TokenDigest(stateToken), Nonce: nonce, Verifier: verifier, ProviderID: p.ID, ProviderKind: p.Credentials.Kind, Generation: state.Generation, Setup: setup, Created: s.now(), Expires: expires, AuthorizationURL: authURL}
	if binding.UserID != "" {
		f := s.flows[database.TokenDigest(raw)]
		f.BindingSession = database.TokenDigest(cookieValue(r, sessionCookie))
		f.BindingUser, f.BindingVersion = binding.UserID, binding.Version
		s.flows[database.TokenDigest(raw)] = f
	}
	s.mu.Unlock()
	setCookie(w, flowCookie, raw, expires.Sub(s.now()), true)
	reply(w, map[string]string{"redirect_path": "/v1/console/auth/redirect"})
}
func (s *Server) redirect(w http.ResponseWriter, r *http.Request) {
	key := database.TokenDigest(cookieValue(r, flowCookie))
	s.mu.Lock()
	s.cleanLocked()
	v, ok := s.flows[key]
	if ok && !v.Started {
		v.Started = true
		s.flows[key] = v
	} else {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		problem(w, 400, "oidc_callback_invalid")
		return
	}
	http.Redirect(w, r, v.AuthorizationURL, http.StatusSeeOther)
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	fail := func(code string) { http.Redirect(w, r, "/login?reason="+code, http.StatusSeeOther) }
	providerKind := "oidc"
	if r.URL.Path == callbackPath("github") {
		providerKind = "github"
	}
	if r.URL.Path == callbackPath("google") {
		providerKind = "google"
	}
	callbackFailure := func(reason string) {
		slog.Warn("Console OAuth failed", "provider", providerKind, "stage", "callback", "reason", reason)
		fail(reason)
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["state"]) != 1 {
		callbackFailure("oauth_callback_invalid")
		return
	}
	rawCookie := cookieValue(r, flowCookie)
	if rawCookie == "" {
		callbackFailure("oauth_cookie_missing")
		return
	}
	key := database.TokenDigest(rawCookie)
	s.mu.Lock()
	s.cleanLocked()
	v, ok := s.flows[key]
	if !ok || !v.Started {
		s.mu.Unlock()
		callbackFailure("oauth_flow_expired")
		return
	}
	if subtle.ConstantTimeCompare([]byte(v.StateDigest), []byte(database.TokenDigest(q.Get("state")))) != 1 {
		s.mu.Unlock()
		callbackFailure("oauth_state_mismatch")
		return
	}
	delete(s.flows, key)
	s.mu.Unlock()
	clearCookie(w, flowCookie)
	if v.BindingUser != "" {
		fail = func(code string) { http.Redirect(w, r, "/account?reason="+code, http.StatusSeeOther) }
		if !s.bindingSessionValid(v) {
			fail("session_expired")
			return
		}
	}
	if len(q["code"]) != 1 || q.Get("code") == "" || q.Get("error") != "" {
		if v.ProviderKind == "github" && q.Get("error") == "access_denied" {
			fail("github_access_denied")
			return
		}
		callbackFailure("oauth_provider_rejected")
		return
	}
	if r.URL.Path != callbackPath(v.ProviderKind) {
		callbackFailure("oauth_callback_mismatch")
		return
	}
	p, err := s.getProvider(r.Context(), v.ProviderID, v.ProviderKind)
	if err != nil {
		fail("oidc_unavailable")
		return
	}
	expectedIssuer := p.Credentials.Issuer
	if p.Credentials.Kind == "github" {
		expectedIssuer = githubAuthorizationIssuer
	}
	if len(q["iss"]) > 1 || q.Has("iss") && q.Get("iss") != expectedIssuer {
		callbackFailure("oauth_issuer_mismatch")
		return
	}
	current, stateErr := s.store.ConsoleState(r.Context())
	if stateErr != nil {
		callbackFailure("oauth_account_failed")
		return
	}
	if current.ProviderID != v.ProviderID || current.Generation != v.Generation {
		callbackFailure("oauth_configuration_changed")
		return
	}
	token, err := p.OAuth.Exchange(oidc.ClientContext(r.Context(), s.httpClient), q.Get("code"), oauth2.VerifierOption(v.Verifier))
	if err != nil {
		if v.ProviderKind == "github" {
			fail(reportGitHubFailure("token_exchange", err))
		} else {
			fail("oidc_callback_invalid")
		}
		return
	}
	issuer, subject, name, err := s.loginIdentity(r.Context(), p, token, v)
	if err != nil {
		if v.ProviderKind == "github" {
			fail(reportGitHubFailure("user_info", err))
		} else {
			fail("oidc_callback_invalid")
		}
		return
	}
	if v.BindingUser != "" {
		if !s.bindingSessionValid(v) {
			fail("session_expired")
			return
		}
		err = s.finishBinding(r.Context(), v, issuer, subject)
		if errors.Is(err, database.ErrConflict) {
			fail("identity_conflict")
			return
		}
		if err != nil {
			callbackFailure("oauth_account_failed")
			return
		}
		http.Redirect(w, r, "/account?bound=1", http.StatusSeeOther)
		return
	}
	u, err := s.store.FinishConsoleLogin(r.Context(), v.Generation, p.ID, issuer, subject, name, v.Setup)
	if err != nil {
		callbackFailure("oauth_account_failed")
		return
	}
	if u.Status == "pending" {
		fail("account_pending")
		return
	}
	if u.Status != "active" {
		fail("forbidden")
		return
	}
	_, ok = s.putSession(w, r, sessionCookie, session{Kind: "user", UserID: u.ID, Version: u.Version, Generation: v.Generation, Expires: s.now().Add(8 * time.Hour), OAuthProviderID: p.ID, OAuthIssuer: issuer, OAuthVerifiedAt: s.now()})
	if !ok {
		fail("service_unavailable")
		return
	}
	// Setup and pre-login authority never survives a successful sign-in.
	s.mu.Lock()
	delete(s.sessions, database.TokenDigest(cookieValue(r, preCookie)))
	delete(s.sessions, database.TokenDigest(cookieValue(r, setupCookie)))
	if v.Setup {
		for k, x := range s.sessions {
			if x.Kind == "setup" {
				delete(s.sessions, k)
			}
		}
		for k, x := range s.flows {
			if x.Setup {
				delete(s.flows, k)
			}
		}
	}
	s.mu.Unlock()
	clearCookie(w, preCookie)
	clearCookie(w, setupCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginIdentity(ctx context.Context, p *provider, token *oauth2.Token, v flow) (string, string, string, error) {
	invalid := errors.New("provider identity verification failed")
	if p.Credentials.Kind == "github" {
		if token.AccessToken == "" || len(token.AccessToken) > 8192 || !strings.EqualFold(token.TokenType, "Bearer") {
			return "", "", "", invalid
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
		if err != nil {
			return "", "", "", err
		}
		r.Header.Set("Authorization", "Bearer "+token.AccessToken)
		r.Header.Set("Accept", "application/vnd.github+json")
		r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := s.httpClient.Do(r)
		if err != nil {
			return "", "", "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", "", "", githubHTTPError{status: resp.StatusCode}
		}
		var user struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Name  string `json:"name"`
			Type  string `json:"type"`
		}
		if json.NewDecoder(resp.Body).Decode(&user) != nil || user.ID <= 0 || user.Type != "User" || user.Login == "" || !protocol.CleanText(user.Login, 128) {
			return "", "", "", invalid
		}
		if user.Name == "" || !protocol.CleanText(user.Name, 128) {
			user.Name = user.Login
		}
		return githubIssuer, strconv.FormatInt(user.ID, 10), user.Name, nil
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 65536 {
		return "", "", "", invalid
	}
	verified, err := p.Verifier.Verify(ctx, raw)
	if err != nil {
		return "", "", "", invalid
	}
	issuer := verified.Issuer
	if p.Credentials.Kind == "google" && issuer == "accounts.google.com" {
		issuer = googleIssuer
	}
	if issuer != p.Credentials.Issuer || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(v.Nonce)) != 1 || verified.IssuedAt.After(s.now().Add(time.Minute)) || verified.IssuedAt.Before(v.Created.Add(-time.Minute)) {
		return "", "", "", invalid
	}
	var claims struct {
		Name            string `json:"name"`
		AuthorizedParty string `json:"azp"`
	}
	if err = verified.Claims(&claims); err != nil || len(verified.Audience) > 1 && claims.AuthorizedParty != p.Credentials.ClientID || claims.AuthorizedParty != "" && claims.AuthorizedParty != p.Credentials.ClientID {
		return "", "", "", invalid
	}
	return issuer, verified.Subject, claims.Name, nil
}
