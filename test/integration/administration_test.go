package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/adminclient"
	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/management"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func TestAdministratorTLSRBACAndLiveRevocation(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	const password = "sample development passphrase"
	admin, err := f.store.CreateUser(t.Context(), "operator", adminauth.Admin, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateUser(t.Context(), "viewer", adminauth.ReadOnly, password); err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(f.root, "pki")
	config, err := tlsconfig.AdministrationServer(tlsconfig.Files{Certificate: filepath.Join(pki, "server-cert.pem"), PrivateKey: filepath.Join(pki, "server-key.pem"), CA: f.ca})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := start(t, config, management.Handler(f.store))
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	c, err := adminclient.New(endpoint.URL, f.ca)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a, err := c.Login(t.Context(), "operator", password)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Login(t.Context(), "viewer", password)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if err := f.store.ConfigureSigner(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	probe, err := agent.NewClient(f.probeURL, f.clientTLS, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	heartbeat := collectHeartbeat(t, f.node)
	heartbeat.Version = 2
	heartbeat.PolicyDigest = strings.Repeat("a", 64)
	heartbeat.TaskState = "ready"
	if err := probe.Heartbeat(t.Context(), heartbeat); err != nil {
		t.Fatal(err)
	}
	submission, _ := json.Marshal(struct {
		AgentID string          `json:"agent_id"`
		Type    string          `json:"task_type"`
		Params  json.RawMessage `json:"params"`
		TTL     int             `json:"ttl_seconds"`
	}{f.node.AgentID, "system.info", json.RawMessage(`{}`), 60})
	expectCode := func(token, method, path string, body []byte, want int) {
		t.Helper()
		_, err := c.Request(t.Context(), token, method, path, body)
		var e *adminclient.APIError
		if !errors.As(err, &e) || e.Status != want {
			t.Fatalf("%s %s got %v want %d", method, path, err, want)
		}
	}
	expectCode("", "GET", "/api/v1/agents", nil, 401)
	expectCode(v.Token, "POST", "/api/v1/tasks", submission, 403)
	expectCode(v.Token, "POST", "/api/v1/enrollment-tokens", []byte(`{"ttl_seconds":60}`), 403)
	expectCode(v.Token, "POST", "/api/v1/agents/"+f.node.AgentID+"/disable", []byte(`{}`), 403)
	for _, path := range []string{"/api/v1/agents?limit=1", "/api/v1/agents/" + f.node.AgentID, "/api/v1/tasks", "/api/v1/audit?limit=50"} {
		if _, err := c.Request(t.Context(), v.Token, "GET", path, nil); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := f.store.Tasks(t.Context(), 0, 100)
	if err != nil || len(rows) != 0 {
		t.Fatal("read dispatched work", err)
	}
	forged := bytes.Replace(submission, []byte(`"ttl_seconds":60`), []byte(`"ttl_seconds":60,"actor_id":"forged","role":"Admin"`), 1)
	expectCode(a.Token, "POST", "/api/v1/tasks", forged, 400)
	data, err := c.Request(t.Context(), a.Token, "POST", "/api/v1/tasks", submission)
	if err != nil {
		t.Fatal(err)
	}
	task, err := protocol.DecodeTask(data)
	if err != nil || task.ActorID != admin.ID {
		t.Fatal("wrong authenticated actor", err)
	}
	if _, err := c.Request(t.Context(), v.Token, "GET", "/api/v1/tasks/"+task.RequestID, nil); err != nil {
		t.Fatal(err)
	}
	// A probe certificate alone is never administrator authority.
	response, err := rawClient(t, f.clientTLS).Get(endpoint.URL + "/api/v1/agents")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("probe certificate granted admin access")
	}
	// Administrator credentials alone cannot enter the mandatory mTLS probe API.
	adminTLS, err := tlsconfig.AdministrationClient(f.ca, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", f.probeURL+"/api/v1/agent/identity", nil)
	req.Header.Set("Authorization", "Bearer "+a.Token)
	if response, err := rawClient(t, adminTLS).Do(req); err == nil {
		response.Body.Close()
		t.Fatal("administrator token replaced probe mTLS")
	}
	// Revocation is checked on an already established TLS connection.
	raw := rawClient(t, adminTLS)
	makeRead := func(trace *httptrace.ClientTrace) int {
		r, _ := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), "GET", endpoint.URL+"/api/v1/auth/me", nil)
		r.Header.Set("Authorization", "Bearer "+v.Token)
		response, err := raw.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.StatusCode
	}
	if makeRead(&httptrace.ClientTrace{}) != 200 {
		t.Fatal("initial session failed")
	}
	if err := f.store.ChangeUser(t.Context(), "viewer", "role", adminauth.Admin); err != nil {
		t.Fatal(err)
	}
	reused := false
	if makeRead(&httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}) != 401 || !reused {
		t.Fatal("stale session accepted or keep-alive not exercised")
	}
	if _, err := c.Request(t.Context(), a.Token, "POST", "/api/v1/auth/logout", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	expectCode(a.Token, "GET", "/api/v1/agents", nil, 401)
	page, err := f.store.Audit(t.Context(), 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(page)
	for _, secret := range []string{a.Token, v.Token, password} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("authentication secret in audit")
		}
	}
	// Node collection remains independently live after administrator logout.
	if _, err := probe.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
}
