package console

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
)

func (s *Server) tokenLogin(w http.ResponseWriter, r *http.Request) {
	pre, ok := s.lookup(r, preCookie, "pre")
	if !ok || !csrf(r, pre) {
		problem(w, 403, "csrf_invalid")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &body, "token") {
		return
	}
	u, generation, err := s.store.LoginConsoleToken(r.Context(), strings.ToLower(strings.TrimSpace(body.Token)))
	if err != nil {
		problem(w, 401, "token_invalid")
		return
	}
	v, ok := s.putSession(w, r, sessionCookie, session{Kind: "user", UserID: u.ID, Version: u.Version, Generation: generation, Expires: s.now().Add(8 * time.Hour)})
	if !ok {
		problem(w, 503, "service_unavailable")
		return
	}
	s.mu.Lock()
	delete(s.sessions, database.TokenDigest(cookieValue(r, preCookie)))
	delete(s.sessions, database.TokenDigest(cookieValue(r, setupCookie)))
	s.mu.Unlock()
	clearCookie(w, preCookie)
	clearCookie(w, setupCookie)
	s.me(w, r, u, v)
}

func (s *Server) account(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, v session) {
	items, err := s.store.ConsoleIdentities(r.Context(), u.ID)
	if err != nil {
		storeProblem(w, err)
		return
	}
	state, err := s.store.ConsoleState(r.Context())
	if err != nil {
		storeProblem(w, err)
		return
	}
	providers := []map[string]string{}
	if state.ProviderID != "" {
		settings, err := s.readProvider(state.ProviderID)
		if err != nil {
			problem(w, 503, "service_unavailable")
			return
		}
		for _, p := range settings {
			providers = append(providers, map[string]string{"kind": p.Kind, "name": providerLabel(p), "issuer": p.Issuer})
		}
	}
	reply(w, map[string]any{"identities": items, "providers": providers, "csrf_token": v.CSRF})
}

func (s *Server) accountProviders(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, v session) {
	state, err := s.store.ConsoleState(r.Context())
	if err != nil {
		storeProblem(w, err)
		return
	}
	s.setupReply(w, v, state)
}
func (s *Server) configureAccountProviders(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, v session) {
	if s.now().Sub(v.Created) > 10*time.Minute {
		problem(w, 403, "reauthentication_required")
		return
	}
	state, err := s.store.ConsoleState(r.Context())
	if err != nil {
		storeProblem(w, err)
		return
	}
	s.saveProvider(w, r, v, state, true)
}
func (s *Server) bindAccount(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, v session) {
	if s.now().Sub(v.Created) > 10*time.Minute {
		problem(w, 403, "reauthentication_required")
		return
	}
	state, err := s.store.ConsoleState(r.Context())
	if err != nil {
		storeProblem(w, err)
		return
	}
	s.startFlow(w, r, state, false, v)
}
func (s *Server) bindingSessionValid(f flow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	v, ok := s.sessions[f.BindingSession]
	return ok && v.Kind == "user" && v.UserID == f.BindingUser && v.Version == f.BindingVersion && v.Generation == f.Generation
}

func (s *Server) finishBinding(ctx context.Context, f flow, issuer, subject string) error {
	// Serialize with logout/session rotation. Database account versions and the
	// provider snapshot are checked again in the same transaction as the insert.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	v, ok := s.sessions[f.BindingSession]
	if !ok || v.Kind != "user" || v.UserID != f.BindingUser || v.Version != f.BindingVersion || v.Generation != f.Generation {
		return database.ErrUnauthorized
	}
	return s.store.BindConsoleIdentity(ctx, f.BindingUser, f.BindingVersion, f.Generation, f.ProviderID, issuer, subject)
}
