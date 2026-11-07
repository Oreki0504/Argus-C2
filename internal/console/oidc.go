package console

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
func (s *Server) readProvider(id string) (providerCredentials, error) {
	var c providerCredentials
	if !identity.Valid(id) {
		return c, errors.New("invalid provider ID")
	}
	b, err := localfile.Read(filepath.Join(s.config.StateDir, "console-provider-"+id+".json"), 8192, true)
	if err == nil {
		err = strictjson.Decode(b, &c, 8192, "issuer", "client_id", "client_secret")
	}
	return c, err
}
func (s *Server) discover(ctx context.Context, id string, c providerCredentials) (*provider, error) {
	u, err := url.Parse(c.Issuer)
	if err != nil || !secureEndpoint(c.Issuer) || u.RawQuery != "" || c.ClientID == "" || !protocol.CleanText(c.ClientID, 512) || !protocol.CleanText(c.ClientSecret, 4096) {
		return nil, errors.New("invalid provider settings")
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
	return &provider{ID: id, Credentials: c, OAuth: oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: endpoint, RedirectURL: s.config.Origin + "/v1/console/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile"}}, Verifier: p.VerifierContext(oidc.ClientContext(context.Background(), s.httpClient), &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256}, Now: s.now})}, nil
}
func (s *Server) getProvider(ctx context.Context, id string) (*provider, error) {
	s.providerMu.Lock()
	defer s.providerMu.Unlock()
	if s.cachedProvider != nil && s.cachedProvider.ID == id {
		return s.cachedProvider, nil
	}
	c, err := s.readProvider(id)
	if err != nil {
		return nil, err
	}
	p, err := s.discover(ctx, id, c)
	if err == nil {
		s.cachedProvider = p
	}
	return p, err
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
	if state.ProviderID != "" {
		c, e := s.readProvider(state.ProviderID)
		if e != nil {
			if !state.SetupOpen(s.now().Unix()) {
				problem(w, 503, "service_unavailable")
				return
			}
		}
		u, _ := url.Parse(c.Issuer)
		if u != nil {
			providerName = &u.Host
		}
	}
	reply(w, map[string]any{"state": status, "provider_name": providerName, "csrf_token": v.CSRF})
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
	c := providerCredentials{}
	step := "provider"
	if state.ProviderID != "" {
		var err error
		c, err = s.readProvider(state.ProviderID)
		if err != nil {
			c = providerCredentials{}
		} else {
			step = "bind"
		}
	}
	reply(w, map[string]string{"step": step, "csrf_token": v.CSRF, "callback_uri": s.config.Origin + "/v1/console/auth/callback", "issuer": c.Issuer, "client_id": c.ClientID})
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
	v, _, ok := s.setupSession(w, r, true)
	if !ok {
		return
	}
	var c providerCredentials
	if !decode(w, r, &c, "issuer", "client_id", "client_secret") {
		return
	}
	id := identity.RandomID()
	p, err := s.discover(r.Context(), id, c)
	if err != nil {
		problem(w, 503, "oidc_unavailable")
		return
	}
	path := filepath.Join(s.config.StateDir, "console-provider-"+id+".json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		problem(w, 503, "service_unavailable")
		return
	}
	err = json.NewEncoder(f).Encode(c)
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
		err = s.store.SetConsoleProvider(r.Context(), v.Generation, id)
	}
	if err != nil {
		_ = os.Remove(path)
		storeProblem(w, err)
		return
	}
	s.providerMu.Lock()
	s.cachedProvider = p
	s.providerMu.Unlock()
	state, err := s.store.ConsoleState(r.Context())
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
	if !decode(w, r, &struct{}{}) {
		return
	}
	p, err := s.getProvider(r.Context(), state.ProviderID)
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
	authURL := p.OAuth.AuthCodeURL(stateToken, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	s.mu.Lock()
	s.cleanLocked()
	if len(s.flows) >= 128 {
		s.mu.Unlock()
		problem(w, 503, "service_unavailable")
		return
	}
	delete(s.flows, database.TokenDigest(cookieValue(r, flowCookie)))
	s.flows[database.TokenDigest(raw)] = flow{StateDigest: database.TokenDigest(stateToken), Nonce: nonce, Verifier: verifier, ProviderID: p.ID, Generation: state.Generation, Setup: setup, Created: s.now(), Expires: expires, AuthorizationURL: authURL}
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
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["state"]) != 1 {
		fail("oidc_callback_invalid")
		return
	}
	key := database.TokenDigest(cookieValue(r, flowCookie))
	s.mu.Lock()
	s.cleanLocked()
	v, ok := s.flows[key]
	if !ok || !v.Started || subtle.ConstantTimeCompare([]byte(v.StateDigest), []byte(database.TokenDigest(q.Get("state")))) != 1 {
		s.mu.Unlock()
		fail("oidc_callback_invalid")
		return
	}
	delete(s.flows, key)
	s.mu.Unlock()
	clearCookie(w, flowCookie)
	if len(q["code"]) != 1 || q.Get("code") == "" || q.Get("error") != "" {
		fail("oidc_callback_invalid")
		return
	}
	p, err := s.getProvider(r.Context(), v.ProviderID)
	if err != nil {
		fail("oidc_unavailable")
		return
	}
	if len(q["iss"]) > 1 || q.Has("iss") && q.Get("iss") != p.Credentials.Issuer {
		fail("oidc_callback_invalid")
		return
	}
	token, err := p.OAuth.Exchange(oidc.ClientContext(r.Context(), s.httpClient), q.Get("code"), oauth2.VerifierOption(v.Verifier))
	if err != nil {
		fail("oidc_callback_invalid")
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 65536 {
		fail("oidc_callback_invalid")
		return
	}
	verified, err := p.Verifier.Verify(r.Context(), raw)
	if err != nil || verified.Issuer != p.Credentials.Issuer || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(v.Nonce)) != 1 || verified.IssuedAt.After(s.now().Add(time.Minute)) || verified.IssuedAt.Before(v.Created.Add(-time.Minute)) {
		fail("oidc_callback_invalid")
		return
	}
	var claims struct {
		Name            string `json:"name"`
		AuthorizedParty string `json:"azp"`
	}
	if err = verified.Claims(&claims); err != nil || len(verified.Audience) > 1 && claims.AuthorizedParty != p.Credentials.ClientID || claims.AuthorizedParty != "" && claims.AuthorizedParty != p.Credentials.ClientID {
		fail("oidc_callback_invalid")
		return
	}
	u, err := s.store.FinishConsoleLogin(r.Context(), v.Generation, p.ID, verified.Issuer, verified.Subject, claims.Name, v.Setup)
	if err != nil {
		fail("oidc_callback_invalid")
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
	_, ok = s.putSession(w, r, sessionCookie, session{Kind: "user", UserID: u.ID, Version: u.Version, Generation: v.Generation, Expires: s.now().Add(8 * time.Hour)})
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
