// Package console serves browser APIs on their own HTTPS origin. Fleet Bearer
// credentials and Agent certificates are never browser authentication.
package console

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/transport"
	"github.com/Oreki0504/Argus-C2/internal/webui"
)

const sessionCookie = "__Host-argus-session"
const preCookie = "__Host-argus-prelogin"
const setupCookie = "__Host-argus-setup"
const flowCookie = "__Host-argus-oidc"

type Config struct {
	Origin, StateDir                   string
	InstallerDir, FleetOrigin, FleetCA string
}
type session struct {
	Kind, UserID, CSRF           string
	Version, Generation          int64
	Created, Last, Expires       time.Time
	TokenAuthenticated           bool
	OAuthProviderID, OAuthIssuer string
	OAuthVerifiedAt              time.Time
}
type flow struct {
	StateDigest, Nonce, Verifier, ProviderID, AuthorizationURL string
	ProviderKind                                               string
	Generation                                                 int64
	Setup, Started                                             bool
	Created, Expires                                           time.Time
	BindingSession, BindingUser                                string
	BindingVersion                                             int64
}
type rate struct {
	Count int
	Until time.Time
}
type Server struct {
	store           *database.Store
	config          Config
	host            string
	mu              sync.Mutex
	sessions        map[string]session
	flows           map[string]flow
	rates           map[string]rate
	providerMu      sync.Mutex
	cachedProviders map[string]*provider
	httpClient      *http.Client
	now             func() time.Time
	installer       *installer
}

func New(store *database.Store, c Config) (*Server, error) {
	if err := transport.ValidateURL(c.Origin); err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.Origin)
	if u.Path != "" || u.Host != strings.ToLower(u.Host) {
		return nil, errors.New("Console origin must be a canonical HTTPS origin without a trailing slash")
	}
	if c.StateDir == "" {
		return nil, errors.New("Console state directory required")
	}
	s := &Server{store: store, config: c, host: u.Host, sessions: map[string]session{}, flows: map[string]flow{}, rates: map[string]rate{}, now: time.Now, httpClient: oidcHTTPClient()}
	var err error
	if s.installer, err = loadInstaller(c); err != nil {
		return nil, err
	}
	// A configured provider must remain readable after restart. Discovery is
	// deferred so an IdP outage does not stop the Fleet listener.
	state, err := store.ConsoleState(context.Background())
	if err != nil {
		return nil, err
	}
	if state.ProviderID != "" && state.Initialized && !state.Recovery {
		if _, err = s.readProvider(state.ProviderID); err != nil {
			return nil, errors.New("Console provider credentials are unavailable")
		}
	}
	return s, nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/console/auth/status", s.authStatus)
	mux.HandleFunc("POST /v1/console/auth/token", s.tokenLogin)
	mux.HandleFunc("GET /v1/console/account", s.authorized(false, s.account))
	mux.HandleFunc("GET /v1/console/account/providers", s.authorized(true, s.accountProviders))
	mux.HandleFunc("POST /v1/console/account/providers", s.authorized(true, s.configureAccountProviders))
	mux.HandleFunc("POST /v1/console/account/bind", s.authorized(false, s.bindAccount))
	mux.HandleFunc("POST /v1/console/account/token/disable", s.authorized(true, s.disableToken))
	mux.HandleFunc("GET /v1/console/setup", s.setupStatus)
	mux.HandleFunc("POST /v1/console/setup/prove", s.prove)
	mux.HandleFunc("POST /v1/console/setup/provider", s.configureProvider)
	mux.HandleFunc("POST /v1/console/setup/bind", func(w http.ResponseWriter, r *http.Request) { s.startLogin(w, r, true) })
	mux.HandleFunc("POST /v1/console/auth/login", func(w http.ResponseWriter, r *http.Request) { s.startLogin(w, r, false) })
	mux.HandleFunc("GET /v1/console/auth/redirect", s.redirect)
	mux.HandleFunc("GET /v1/console/auth/callback", s.callback)
	mux.HandleFunc("GET /v1/console/auth/callback/google", s.callback)
	mux.HandleFunc("GET /v1/console/auth/callback/github", s.callback)
	mux.HandleFunc("GET /v1/me", s.authorized(false, s.me))
	mux.HandleFunc("POST /v1/console/auth/logout", s.authorized(false, s.logout))
	s.managementRoutes(mux)
	s.installerRoutes(mux)
	mux.HandleFunc("GET /v1/console/public/summary", s.summary)
	mux.HandleFunc("GET /v1/console/public/nodes/{id}/history", s.history)
	mux.HandleFunc("GET /v1/console/summary", s.authorized(false, func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) { s.summary(w, r) }))
	mux.HandleFunc("GET /v1/console/nodes/{id}/history", s.authorized(false, func(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) { s.history(w, r) }))
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) { problem(w, 404, "not_found") })
	mux.HandleFunc("/v1", func(w http.ResponseWriter, r *http.Request) { problem(w, 404, "not_found") })
	mux.Handle("/", webui.Handler())
	slots := make(chan struct{}, 24)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		if r.TLS == nil || r.Host != s.host {
			problem(w, 400, "invalid_request")
			return
		}
		if r.Header.Get("Authorization") != "" {
			problem(w, 401, "session_expired")
			return
		}
		if len(r.URL.RawQuery) > 8192 {
			problem(w, 400, "invalid_request")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != s.config.Origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				problem(w, 403, "csrf_invalid")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") && !s.allow(r) {
			problem(w, 429, "rate_limited")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			problem(w, 503, "service_unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) allow(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	kind := "read"
	limit := 120
	if strings.Contains(r.URL.Path, "/auth/") || strings.Contains(r.URL.Path, "/setup") {
		kind = "auth"
		limit = 30
	}
	key := kind + ":" + ip
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	v := s.rates[key]
	if v.Until.IsZero() {
		if len(s.rates) >= 2048 {
			return false
		}
		v.Until = s.now().Add(time.Minute)
	}
	if v.Count >= limit {
		return false
	}
	v.Count++
	s.rates[key] = v
	return true
}
func (s *Server) cleanLocked() {
	now := s.now()
	for k, v := range s.sessions {
		if !now.Before(v.Expires) || (v.Kind == "user" && now.Sub(v.Last) >= 30*time.Minute) {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.flows {
		if !now.Before(v.Expires) {
			delete(s.flows, k)
		}
	}
	for k, v := range s.rates {
		if !now.Before(v.Until) {
			delete(s.rates, k)
		}
	}
}
func cookieValue(r *http.Request, name string) string {
	value := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value = c.Value
			count++
		}
	}
	if count != 1 || len(value) > 128 {
		return ""
	}
	return value
}
func setCookie(w http.ResponseWriter, name, value string, ttl time.Duration, lax bool) {
	same := http.SameSiteStrictMode
	if lax {
		same = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: same, MaxAge: int(ttl.Seconds())})
}
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
func (s *Server) lookup(r *http.Request, name, kind string) (session, bool) {
	raw := cookieValue(r, name)
	if raw == "" {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	key := database.TokenDigest(raw)
	v, ok := s.sessions[key]
	if !ok || v.Kind != kind {
		return session{}, false
	}
	v.Last = s.now()
	s.sessions[key] = v
	return v, true
}
func (s *Server) putSession(w http.ResponseWriter, r *http.Request, name string, v session) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	// Rotate the browser's previous credential, never adopt a caller ID.
	delete(s.sessions, database.TokenDigest(cookieValue(r, name)))
	if len(s.sessions) >= 1024 {
		return session{}, false
	}
	if v.Kind == "user" {
		count := 0
		oldestKey := ""
		var oldest time.Time
		for k, existing := range s.sessions {
			if existing.Kind == "user" && existing.UserID == v.UserID {
				count++
				if oldestKey == "" || existing.Created.Before(oldest) {
					oldest = existing.Created
					oldestKey = k
				}
			}
		}
		if count >= 8 {
			delete(s.sessions, oldestKey)
		}
	}
	raw := identity.RandomID() + identity.RandomID()
	v.CSRF = identity.RandomID() + identity.RandomID()
	v.Created = s.now()
	v.Last = v.Created
	s.sessions[database.TokenDigest(raw)] = v
	setCookie(w, name, raw, v.Expires.Sub(s.now()), false)
	return v, true
}
func csrf(r *http.Request, v session) bool {
	return len(r.Header.Values("X-CSRF-Token")) == 1 && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(v.CSRF)) == 1
}
func (s *Server) authorized(admin bool, next func(http.ResponseWriter, *http.Request, database.ConsoleUser, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := s.lookup(r, sessionCookie, "user")
		if !ok {
			problem(w, 401, "session_expired")
			return
		}
		u, err := s.store.ConsoleUser(r.Context(), v.UserID)
		state, stateErr := s.store.ConsoleState(r.Context())
		if err != nil && !errors.Is(err, database.ErrNotFound) || stateErr != nil {
			problem(w, 503, "service_unavailable")
			return
		}
		if err != nil || u.Status != "active" || u.Version != v.Version || state.Generation != v.Generation || !state.Initialized || state.Recovery {
			clearCookie(w, sessionCookie)
			problem(w, 401, "session_expired")
			return
		}
		if admin && u.Role != "Admin" {
			problem(w, 403, "forbidden")
			return
		}
		if v.TokenAuthenticated {
			enabled, err := s.store.ConsoleTokenAvailable(r.Context())
			if err != nil {
				problem(w, 503, "service_unavailable")
				return
			}
			if !enabled {
				clearCookie(w, sessionCookie)
				problem(w, 401, "session_expired")
				return
			}
		}
		if r.Method == http.MethodPost && !csrf(r, v) {
			problem(w, 403, "csrf_invalid")
			return
		}
		ctx := database.WithConsoleActor(r.Context(), u.ID, u.Version, v.Generation, admin)
		if v.TokenAuthenticated {
			ctx = database.WithConsoleTokenSession(ctx)
		}
		next(w, r.WithContext(ctx), u, v)
	}
}
func (s *Server) me(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, v session) {
	caps := []string{"summary:read"}
	if u.Role == "Admin" {
		caps = append(caps, "tasks:read", "tasks:write", "agents:read", "agents:write", "audit:read", "users:read", "users:write")
	}
	reply(w, map[string]any{"principal_id": u.ID, "name": u.Name, "role": u.Role, "csrf_token": v.CSRF, "capabilities": caps})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
	if !decode(w, r, &struct{}{}) {
		return
	}
	if err := s.store.ConsoleAudit(r.Context(), "web:"+u.ID, "console.logout", u.ID, "succeeded"); err != nil {
		storeProblem(w, err)
		return
	}
	s.mu.Lock()
	delete(s.sessions, database.TokenDigest(cookieValue(r, sessionCookie)))
	s.mu.Unlock()
	clearCookie(w, sessionCookie)
	reply(w, struct{}{})
}
func decode(w http.ResponseWriter, r *http.Request, v any, fields ...string) bool {
	return decodeAlternatives(w, r, v, fields)
}
func decodeAlternatives(w http.ResponseWriter, r *http.Request, v any, variants ...[]string) bool {
	defer r.Body.Close()
	if len(r.Header.Values("Content-Type")) != 1 || !strictjson.MediaType(r.Header.Get("Content-Type")) {
		problem(w, 400, "invalid_request")
		return false
	}
	b, err := strictjson.Read(http.MaxBytesReader(w, r.Body, 16384), 16384)
	if err == nil {
		for _, fields := range variants {
			err = strictjson.Decode(b, v, 16384, fields...)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		problem(w, 400, "invalid_request")
		return false
	}
	return true
}
func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
}
func storeProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, database.ErrUnauthorized):
		problem(w, 401, "session_expired")
	case errors.Is(err, database.ErrSetupClosed):
		problem(w, 403, "setup_closed")
	case errors.Is(err, database.ErrBootstrapInvalid):
		problem(w, 403, "bootstrap_invalid")
	case errors.Is(err, database.ErrSelfChange):
		problem(w, 409, "self_change")
	case errors.Is(err, database.ErrLastAdmin):
		problem(w, 409, "last_admin")
	case errors.Is(err, database.ErrNotFound):
		problem(w, 404, "not_found")
	case errors.Is(err, database.ErrConflict):
		problem(w, 409, "user_conflict")
	default:
		problem(w, 503, "service_unavailable")
	}
}
