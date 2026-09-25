// Package management exposes a separate, explicitly enabled administrator API.
package management

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxRequestBytes = 8192
const MaxResponseBytes = 4 * 1024 * 1024
const LoginPath = "/api/v1/auth/login"

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func DecodeLogin(data []byte) (LoginRequest, error) {
	var r LoginRequest
	if err := strictjson.Decode(data, &r, 1024, "username", "password"); err != nil {
		return r, err
	}
	if !adminauth.Username(r.Username) || !adminauth.PasswordInput(r.Password) {
		return r, state.ErrManagementRequest
	}
	return r, nil
}
func DecodeSubmit(data []byte) (state.ManagementRequest, error) {
	var r struct {
		AgentID    string            `json:"agent_id"`
		Type       protocol.TaskType `json:"task_type"`
		Params     json.RawMessage   `json:"params"`
		TTLSeconds int               `json:"ttl_seconds"`
	}
	if err := strictjson.Decode(data, &r, MaxRequestBytes, "agent_id", "task_type", "params", "ttl_seconds"); err != nil {
		return state.ManagementRequest{}, err
	}
	return state.ManagementRequest{Operation: "submit", AgentID: r.AgentID, Type: r.Type, Params: r.Params, TTLSeconds: r.TTLSeconds}, nil
}
func bearer(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", state.ErrAdminUnauthorized
	}
	value := strings.TrimPrefix(values[0], "Bearer ")
	if !identity.Hex(value, 64) {
		return "", state.ErrAdminUnauthorized
	}
	return value, nil
}
func body(r *http.Request, limit int) ([]byte, error) {
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) != 0 || r.ContentLength <= 0 || r.ContentLength > int64(limit) || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Encoding") != "" {
		return nil, state.ErrManagementRequest
	}
	return strictjson.Read(r.Body, limit)
}
func page(r *http.Request, operation string) (state.ManagementRequest, error) {
	result := state.ManagementRequest{Operation: operation, Limit: 50}
	q, err := urlQuery(r)
	if err != nil {
		return result, err
	}
	if value, ok := q["limit"]; ok {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 50 || strconv.Itoa(n) != value {
			return result, state.ErrManagementRequest
		}
		result.Limit = n
	}
	if value, ok := q["after"]; ok {
		if operation == "agents" {
			if !identity.Hex(value, 32) {
				return result, state.ErrManagementRequest
			}
			result.AfterNode = value
		} else {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 || strconv.FormatInt(n, 10) != value {
				return result, state.ErrManagementRequest
			}
			result.After = n
		}
	}
	return result, nil
}
func urlQuery(r *http.Request) (map[string]string, error) {
	result := map[string]string{}
	if r.URL.RawQuery == "" {
		if r.URL.ForceQuery {
			return nil, state.ErrManagementRequest
		}
		return result, nil
	}
	for _, part := range strings.Split(r.URL.RawQuery, "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || (k != "after" && k != "limit") || v == "" || strings.ContainsAny(v, "%+;") {
			return nil, state.ErrManagementRequest
		}
		if _, exists := result[k]; exists {
			return nil, state.ErrManagementRequest
		}
		result[k] = v
	}
	return result, nil
}

// There is no browser/session-cookie mode, CORS, proxy identity, or client-
// supplied role/actor. Malformed traffic is shed before reading unbounded data.
func Handler(store *state.Store) http.Handler {
	slots := make(chan struct{}, 8)
	var mu sync.Mutex
	var window time.Time
	count := 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(status int, code string) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
		}
		if store == nil {
			fail(503, "unavailable")
			return
		}
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			fail(401, "unauthorized")
			return
		}
		mu.Lock()
		now := time.Now()
		if now.Sub(window) >= time.Minute {
			window = now
			count = 0
		}
		allowed := count < 120
		if allowed {
			count++
		}
		mu.Unlock()
		if !allowed {
			w.Header().Set("Retry-After", "60")
			fail(429, "rate_limited")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			fail(429, "rate_limited")
			return
		}
		if r.URL.RawPath != "" || len(r.RequestURI) > 512 || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 || r.Header.Get("Content-Encoding") != "" || len(r.TransferEncoding) != 0 {
			fail(400, "invalid_request")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		var result any
		var err error
		if r.URL.Path == LoginPath {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				fail(405, "method_not_allowed")
				return
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Authorization")) != 0 {
				fail(400, "invalid_request")
				return
			}
			data, e := body(r, 1024)
			if e != nil {
				fail(400, "invalid_request")
				return
			}
			req, e := DecodeLogin(data)
			if e != nil {
				fail(400, "invalid_request")
				return
			}
			result, err = store.Login(ctx, req.Username, req.Password, audit.Peer(r.RemoteAddr))
		} else {
			token, e := bearer(r)
			if e != nil {
				fail(401, "unauthorized")
				return
			}
			req := state.ManagementRequest{}
			path := r.URL.Path
			switch {
			case path == "/api/v1/agents":
				req.Operation = "agents"
			case path == "/api/v1/tasks":
				req.Operation = "tasks"
				if r.Method == http.MethodPost {
					req.Operation = "submit"
				}
			case path == "/api/v1/audit":
				req.Operation = "audit"
			case path == "/api/v1/auth/me":
				req.Operation = "whoami"
			case path == "/api/v1/auth/logout":
				req.Operation = "logout"
			case path == "/api/v1/auth/revoke":
				req.Operation = "revoke"
			case path == "/api/v1/enrollment-tokens":
				req.Operation = "token"
			case strings.HasPrefix(path, "/api/v1/agents/"):
				id := strings.TrimPrefix(path, "/api/v1/agents/")
				req.Operation = "agents"
				req.Limit = 1
				if strings.HasSuffix(id, "/disable") {
					req.Operation = "disable"
					id = strings.TrimSuffix(id, "/disable")
				}
				if !identity.Hex(id, 32) {
					fail(404, "not_found")
					return
				}
				req.AgentID = id
			case strings.HasPrefix(path, "/api/v1/tasks/"):
				id := strings.TrimPrefix(path, "/api/v1/tasks/")
				if !identity.Hex(id, 32) {
					fail(404, "not_found")
					return
				}
				req.Operation = "tasks"
				req.RequestID = id
				req.Limit = 1
			default:
				fail(404, "not_found")
				return
			}
			post := req.Operation == "submit" || req.Operation == "token" || req.Operation == "disable" || req.Operation == "logout" || req.Operation == "revoke"
			method := http.MethodGet
			if post {
				method = http.MethodPost
			}
			if r.Method != method {
				w.Header().Set("Allow", method)
				fail(405, "method_not_allowed")
				return
			}
			if post {
				if r.URL.RawQuery != "" || r.URL.ForceQuery {
					fail(400, "invalid_request")
					return
				}
				data, e := body(r, MaxRequestBytes)
				if e != nil {
					fail(400, "invalid_request")
					return
				}
				switch req.Operation {
				case "submit":
					req, err = DecodeSubmit(data)
				case "token":
					var v struct {
						TTL int `json:"ttl_seconds"`
					}
					err = strictjson.Decode(data, &v, 256, "ttl_seconds")
					req.TTLSeconds = v.TTL
				default:
					var v struct{}
					err = strictjson.Decode(data, &v, 64)
				}
				if err != nil {
					fail(400, "invalid_request")
					return
				}
			} else {
				if r.ContentLength != 0 {
					fail(400, "invalid_request")
					return
				}
				if req.Operation != "whoami" && req.AgentID == "" && req.RequestID == "" {
					req, err = page(r, req.Operation)
				} else if r.URL.RawQuery != "" || r.URL.ForceQuery {
					err = state.ErrManagementRequest
				}
				if err != nil {
					fail(400, "invalid_request")
					return
				}
			}
			result, err = store.Manage(ctx, token, audit.Peer(r.RemoteAddr), req)
		}
		if err != nil {
			switch {
			case errors.Is(err, state.ErrAdminUnauthorized):
				fail(401, "unauthorized")
			case errors.Is(err, state.ErrAdminForbidden):
				fail(403, "forbidden")
			case errors.Is(err, state.ErrAdminLimited):
				w.Header().Set("Retry-After", "60")
				fail(429, "rate_limited")
			case errors.Is(err, state.ErrManagementRequest):
				fail(400, "invalid_request")
			case errors.Is(err, state.ErrManagementNotFound):
				fail(404, "not_found")
			case errors.Is(err, state.ErrManagementConflict):
				fail(409, "operation_rejected")
			default:
				fail(503, "unavailable")
			}
			return
		}
		// Buffer and bound the response before releasing any data to the network.
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(result); err != nil || b.Len() > MaxResponseBytes {
			fail(503, "unavailable")
			return
		}
		_, _ = w.Write(b.Bytes())
	})
}
