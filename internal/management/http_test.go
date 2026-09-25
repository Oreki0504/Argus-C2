package management

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/state"
)

func TestStrictManagementFraming(t *testing.T) {
	s, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := Handler(s)
	for _, tc := range []struct {
		path, method, body string
		mutate             func(*http.Request)
		want               int
	}{
		{LoginPath, "POST", `{"username":"operator","password":"test","role":"Admin"}`, nil, 400},
		{LoginPath, "POST", `{"username":"operator","username":"other","password":"test"}`, nil, 400},
		{LoginPath, "POST", `{"username":"operator","password":null}`, nil, 400},
		{LoginPath, "POST", strings.Repeat(" ", 1025), nil, 400},
		{LoginPath, "POST", `{}`, func(r *http.Request) { r.TLS = nil }, 401},
		{LoginPath, "POST", `{}`, func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 400},
		{LoginPath, "POST", `{}`, func(r *http.Request) { r.Header.Set("Cookie", "session=secret") }, 400},
		{LoginPath, "POST", `{}`, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{LoginPath, "POST", `{}`, func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		{"/api/v1/agents", "GET", "", nil, 401},
		{"/api/v1/agents", "GET", "", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
			r.Header.Add("Authorization", "Bearer "+strings.Repeat("b", 64))
		}, 401},
		{"/api/v1/agents?token=secret", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64)) }, 400},
		{"/api/v1/agents?limit=1&limit=2", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64)) }, 400},
		{"/api/v1/agents?limit=51", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64)) }, 400},
		{"/api/v1/agents?limit=%31", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64)) }, 400},
		{"/api/v1/agents", "OPTIONS", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64)) }, 405},
	} {
		r := httptest.NewRequest(tc.method, "https://127.0.0.1"+tc.path, bytes.NewReader([]byte(tc.body)))
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		r.Header.Set("Content-Type", "application/json")
		if tc.mutate != nil {
			tc.mutate(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s %s: %d want %d", tc.method, tc.path, w.Code, tc.want)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("unexpected browser credentials/cache headers")
		}
	}
}
func FuzzManagementRequests(f *testing.F) {
	f.Add([]byte(`{"username":"operator","password":"sample password only"}`))
	f.Add([]byte(`{"agent_id":"11111111111111111111111111111111","task_type":"ssh.audit","params":{"profile_id":"host"},"ttl_seconds":60}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := DecodeLogin(b); err == nil {
			encoded, _ := json.Marshal(r)
			if _, err := DecodeLogin(encoded); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := DecodeSubmit(b); err == nil && len(b) > MaxRequestBytes {
			t.Fatal("submit size bypass")
		}
	})
}
