// Package api translates HTTP messages; database and enrollment own state changes.
package api

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Server struct {
	Store      *database.Store
	Enrollment enrollment.Service
	Admins     auth.Config
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		metadata, ok := agentMetadata(w, r)
		if !ok {
			return
		}
		var v protocol.EnrollmentRequest
		if !decode(w, r, &v, 8192, "token", "hostname", "csr") {
			return
		}
		if _, err := enrollment.ParseCSR(v.CSR); err != nil || len(v.Token) < 40 || len(v.Token) > 256 || v.Hostname == "" || !protocol.CleanText(v.Hostname, 255) {
			problem(w, 400, "invalid enrollment parameters")
			return
		}
		out, e := s.Enrollment.Enroll(r.Context(), v, metadata)
		reply(w, out, e)
	})
	mux.HandleFunc("GET /v1/health", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		e := s.Store.DB.PingContext(r.Context())
		reply(w, map[string]string{"status": "ok"}, e)
	}))
	mux.HandleFunc("GET /v1/nodes", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		out, e := s.Store.Nodes(r.Context(), r.URL.Query().Get("after"))
		reply(w, out, e)
	}))
	mux.HandleFunc("POST /v1/nodes/{id}/disable", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		if !decode(w, r, &struct{}{}, 256) {
			return
		}
		reply(w, struct{}{}, s.Store.Disable(r.Context(), u.Name, r.PathValue("id")))
	}))
	mux.HandleFunc("POST /v1/enrollment-tokens", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		var v struct {
			TTL int `json:"ttl_seconds"`
		}
		if !decode(w, r, &v, 256, "ttl_seconds") {
			return
		}
		if v.TTL < 60 || v.TTL > 3600 {
			problem(w, 400, "invalid token lifetime")
			return
		}
		token, e := s.Store.CreateToken(r.Context(), u.Name, time.Duration(v.TTL)*time.Second)
		reply(w, map[string]string{"token": token}, e)
	}))
	mux.HandleFunc("POST /v1/tasks", s.admin(true, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		b, e := body(w, r, protocol.MaxPayloadBytes)
		if e != nil {
			problem(w, 400, "invalid request body")
			return
		}
		v, e := protocol.DecodeTaskRequest(b)
		if e != nil {
			problem(w, 400, "invalid task parameters")
			return
		}
		out, e := s.Store.CreateTask(r.Context(), u.Name, v)
		reply(w, out, e)
	}))
	mux.HandleFunc("GET /v1/tasks", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		s.tasks(w, r)
	}))
	mux.HandleFunc("GET /v1/tasks/{id}", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		out, e := s.Store.Task(r.Context(), r.PathValue("id"))
		reply(w, out, e)
	}))
	mux.HandleFunc("GET /v1/audit", s.admin(false, func(w http.ResponseWriter, r *http.Request, u auth.User) {
		after := int64(0)
		if raw := r.URL.Query().Get("after"); raw != "" {
			var e error
			after, e = strconv.ParseInt(raw, 10, 64)
			if e != nil || after < 0 {
				problem(w, 400, "invalid cursor")
				return
			}
		}
		out, e := s.Store.AuditEvents(r.Context(), after)
		reply(w, out, e)
	}))
	mux.HandleFunc("POST /v1/agent/heartbeat", s.node(func(w http.ResponseWriter, r *http.Request, c *x509.Certificate) {
		var v protocol.Heartbeat
		if !decode(w, r, &v, 1024, "hostname") {
			return
		}
		if v.Hostname == "" || !protocol.CleanText(v.Hostname, 255) {
			problem(w, 400, "invalid hostname")
			return
		}
		reply(w, struct{}{}, s.Store.Heartbeat(r.Context(), c, v.Hostname, protocol.AgentMetadata{ProtocolVersion: protocol.Version, AgentVersion: r.Header.Get(protocol.AgentVersionHeader)}))
	}))
	mux.HandleFunc("POST /v1/agent/poll", s.node(func(w http.ResponseWriter, r *http.Request, c *x509.Certificate) {
		if !decode(w, r, &struct{}{}, 256) {
			return
		}
		out, e := s.Store.Poll(r.Context(), c)
		if e == nil && out == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		reply(w, out, e)
	}))
	mux.HandleFunc("POST /v1/agent/tasks/{id}/running", s.node(func(w http.ResponseWriter, r *http.Request, c *x509.Certificate) {
		if !decode(w, r, &struct{}{}, 256) {
			return
		}
		reply(w, struct{}{}, s.Store.Running(r.Context(), c, r.PathValue("id")))
	}))
	mux.HandleFunc("POST /v1/agent/results", s.node(func(w http.ResponseWriter, r *http.Request, c *x509.Certificate) {
		b, e := body(w, r, protocol.MaxResultBytes)
		if e != nil {
			problemCode(w, 400, "result_invalid", "invalid result size")
			return
		}
		v, e := protocol.DecodeResult(b)
		if e != nil {
			problemCode(w, 400, "result_invalid", "invalid result")
			return
		}
		reply(w, struct{}{}, s.Store.SubmitResult(r.Context(), c, v))
	}))
	mux.HandleFunc("POST /v1/agent/renew", s.node(func(w http.ResponseWriter, r *http.Request, c *x509.Certificate) {
		var v protocol.RenewalRequest
		if !decode(w, r, &v, 8192, "csr") {
			return
		}
		if _, e := enrollment.ParseCSR(v.CSR); e != nil {
			problem(w, 400, "invalid CSR")
			return
		}
		out, e := s.Enrollment.Renew(r.Context(), c, v.CSR)
		reply(w, out, e)
	}))
	slots := make(chan struct{}, 64)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(protocol.VersionHeader, strconv.Itoa(protocol.Version))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil {
			problem(w, 400, "HTTPS required")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			mux.ServeHTTP(w, r)
		default:
			problem(w, 503, "server busy")
		}
	})
}
func (s *Server) admin(write bool, next func(http.ResponseWriter, *http.Request, auth.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") {
			problem(w, 401, "unauthorized")
			return
		}
		u, e := s.Admins.Authenticate(strings.TrimPrefix(raw, "Bearer "))
		if e != nil {
			problem(w, 401, "unauthorized")
			return
		}
		if write && u.Role != "Admin" {
			problem(w, 403, "forbidden")
			return
		}
		next(w, r, u)
	}
}
func (s *Server) node(next func(http.ResponseWriter, *http.Request, *x509.Certificate)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			problem(w, 401, "client certificate required")
			return
		}
		if _, ok := agentMetadata(w, r); !ok {
			return
		}
		c := r.TLS.PeerCertificates[0]
		if _, e := identity.FromCertificate(c); e != nil {
			problem(w, 401, "invalid node identity")
			return
		}
		// Fingerprint, validity and disabled status are checked in the same
		// transaction as each node operation, including requests on reused TLS.
		next(w, r, c)
	}
}
func body(w http.ResponseWriter, r *http.Request, limit int) ([]byte, error) {
	defer r.Body.Close()
	if len(r.Header.Values("Content-Type")) != 1 || !strictjson.MediaType(r.Header.Get("Content-Type")) {
		return nil, errors.New("expected JSON")
	}
	return strictjson.Read(http.MaxBytesReader(w, r.Body, int64(limit)), limit)
}
func decode(w http.ResponseWriter, r *http.Request, v any, limit int, fields ...string) bool {
	b, e := body(w, r, limit)
	if e == nil {
		e = strictjson.Decode(b, v, limit, fields...)
	}
	if e != nil {
		problem(w, 400, "invalid request schema or size")
		return false
	}
	return true
}
func problem(w http.ResponseWriter, status int, message string) {
	code := map[int]string{400: "invalid_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "state_conflict", 500: "operation_failed", 503: "server_busy"}[status]
	problemCode(w, status, code, message)
}
func problemCode(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}
func reply(w http.ResponseWriter, v any, e error) {
	if e != nil {
		switch {
		case errors.Is(e, database.ErrResultConflict):
			problemCode(w, 409, "result_conflict", "result differs from stored outcome")
		case errors.Is(e, database.ErrTaskRejected):
			problemCode(w, 409, "task_rejected", "task cannot accept result")
		case errors.Is(e, database.ErrTaskNotFound):
			problemCode(w, 404, "task_not_found", "assigned task not found")
		case errors.Is(e, database.ErrInvalidResult):
			problemCode(w, 400, "result_invalid", "invalid result for assigned task")
		case errors.Is(e, database.ErrInvalidRenewal):
			problemCode(w, 400, "renewal_key_mismatch", "renewal must retain its key")
		case errors.Is(e, database.ErrUnauthorized):
			problem(w, 401, "unauthorized")
		case errors.Is(e, database.ErrConflict):
			problem(w, 409, "state conflict")
		case errors.Is(e, database.ErrNotFound):
			problem(w, 404, "not found")
		default:
			problem(w, 500, "operation failed")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func agentMetadata(w http.ResponseWriter, r *http.Request) (protocol.AgentMetadata, bool) {
	m := protocol.AgentMetadata{ProtocolVersion: protocol.Version, AgentVersion: r.Header.Get(protocol.AgentVersionHeader)}
	if len(r.Header.Values(protocol.VersionHeader)) != 1 || r.Header.Get(protocol.VersionHeader) != strconv.Itoa(protocol.Version) || len(r.Header.Values(protocol.AgentVersionHeader)) != 1 || !m.Valid() {
		problemCode(w, 426, "protocol_incompatible", "unsupported agent protocol or metadata")
		return m, false
	}
	return m, true
}
