package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func renewalFiles(f *enrollmentFixture, dir string) tlsconfig.Files {
	return tlsconfig.Files{Certificate: filepath.Join(dir, "probe-cert.pem"), PrivateKey: filepath.Join(dir, "probe-key.pem"), CA: f.ca}
}
func renewalServer(t *testing.T, f *enrollmentFixture, renew http.Handler, sink server.TelemetryStore) string {
	t.Helper()
	pki := filepath.Join(f.root, "pki")
	config, err := tlsconfig.Server(tlsconfig.Files{Certificate: filepath.Join(pki, "server-cert.pem"), PrivateKey: filepath.Join(pki, "server-key.pem"), CA: f.ca}, f.store)
	if err != nil {
		t.Fatal(err)
	}
	return start(t, config, server.HandlerWithRenewal(f.store, renew, sink)).URL
}

func TestRenewalLostResponsePreservesReplayAndPendingResult(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service, err := server.NewTaskService(t.Context(), f.store, key)
	if err != nil {
		t.Fatal(err)
	}
	handler := enrollment.RenewalHandler(f.store, f.issuer)
	var lose atomic.Bool
	lose.Store(true)
	url := renewalServer(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lose.Swap(false) {
			recorded := httptest.NewRecorder()
			handler.ServeHTTP(recorded, r)
			if recorded.Code != 200 {
				t.Errorf("issuance failed before injected lost response: %d", recorded.Code)
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		handler.ServeHTTP(w, r)
	}), service)
	c, err := agent.NewClient(url, f.clientTLS, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	policyBytes, err := os.ReadFile("../../examples/task-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Decode(policyBytes)
	if err != nil {
		t.Fatal(err)
	}
	p.Telemetry.SampleMilliseconds = 100
	policyBytes, _ = json.Marshal(p)
	path := filepath.Join(f.root, "policy.json")
	if err := os.WriteFile(path, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	replay := filepath.Join(f.root, "replay")
	if err := probe.Initialize(replay, f.node, pub); err != nil {
		t.Fatal(err)
	}
	worker, err := probe.Open(replay, f.node, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if worker != nil {
			worker.Close()
		}
	}()
	h := collectHeartbeat(t, f.node)
	h.Version = 2
	h.PolicyDigest, _ = p.Digest()
	h.TaskState = "ready"
	if err := c.Heartbeat(t.Context(), h); err != nil {
		t.Fatal(err)
	}
	task, err := f.store.Enqueue(t.Context(), f.node.AgentID, protocol.SystemInfo, "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := c.Poll(t.Context(), h.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.NewEngine(worker, path, url).Process(t.Context(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the completed result pending while TLS credentials change.
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	worker = nil
	oldDir := filepath.Join(f.root, "probe")
	stage := filepath.Join(f.root, "renewal")
	if err := agent.PrepareRenewal(url, renewalFiles(f, oldDir), f.node, stage); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(stage, "probe-key.pem"))
	if _, err := agent.RequestRenewal(t.Context(), url, renewalFiles(f, oldDir), f.node, stage); err == nil {
		t.Fatal("injected lost response was ignored")
	}
	if _, err := os.Stat(filepath.Join(stage, "identity.json")); !os.IsNotExist(err) {
		t.Fatal("partial generation marked complete", err)
	}
	first, err := agent.RequestRenewal(t.Context(), url, renewalFiles(f, oldDir), f.node, stage)
	if err != nil {
		t.Fatal(err)
	}
	second, err := agent.RequestRenewal(t.Context(), url, renewalFiles(f, oldDir), f.node, stage)
	if err != nil || first != second {
		t.Fatal("explicit retry changed committed response", err)
	}
	after, _ := os.ReadFile(filepath.Join(stage, "probe-key.pem"))
	if !bytes.Equal(before, after) {
		t.Fatal("retry replaced staged private key")
	}
	newNode, err := identity.LoadNode(filepath.Join(stage, "identity.json"))
	if err != nil || newNode != f.node {
		t.Fatal("renewal changed identity", err)
	}
	config, err := tlsconfig.Client(renewalFiles(f, stage), f.node, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	next, err := agent.NewClient(url, config, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err := next.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	worker, err = probe.Open(replay, f.node, pub)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := probe.NewEngine(worker, path, url).Process(t.Context(), envelope)
	if err != nil || !bytes.Equal(cached, result) {
		t.Fatal("credential activation reset replay or changed result", err)
	}
	ack, err := next.SubmitResult(t.Context(), cached)
	if err != nil || ack.RequestID != task.RequestID {
		t.Fatal("new credential failed to deliver pending result", err)
	}
	if err := worker.Acknowledge(t.Context(), ack.RequestID, ack.ResultDigest); err != nil {
		t.Fatal(err)
	}
	page, err := probe.ReadAudit(t.Context(), replay, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, r := range page.Records {
		if r.Event.Kind == "task_accepted" && r.Event.RequestID == task.RequestID {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("task admitted more than once after renewal", accepted)
	}
	// Establish and reuse the old credential's real TLS connection across revoke.
	raw := rawClient(t, f.clientTLS)
	var reused bool
	get := func() int {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", url+server.IdentityPath, nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}))
		resp, err := raw.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if get() != 200 {
		t.Fatal("old credential not usable within overlap")
	}
	if err := f.store.RevokeCertificate(t.Context(), f.node.AgentID, identity.Fingerprint(f.clientTLS.Certificates[0].Leaf)); err != nil {
		t.Fatal(err)
	}
	if get() != 401 || !reused {
		t.Fatal("revocation not applied to reused connection", reused)
	}
	if _, err := next.Connect(t.Context()); err != nil {
		t.Fatal("old revoke affected new generation", err)
	}
	if _, err := agent.RequestRenewal(t.Context(), url, renewalFiles(f, oldDir), f.node, stage); err == nil {
		t.Fatal("revoked credential retrieved renewal")
	}
	if err := f.store.Disable(t.Context(), f.node.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Connect(t.Context()); err == nil {
		t.Fatal("node disablement missed renewed leaf")
	}
}

func TestRenewalEndpointRejectsUntrustedAndAmbiguousRequests(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	url := renewalServer(t, f, enrollment.RenewalHandler(f.store, f.issuer), f.store)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	request := protocol.RenewalRequest{Version: 1, RenewalID: identity.RandomID(), CSR: base64.RawURLEncoding.EncodeToString(der)}
	valid, _ := json.Marshal(request)
	csrWithName, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"another-host"}}, key)
	changed := request
	changed.CSR = base64.RawURLEncoding.EncodeToString(csrWithName)
	badCSR, _ := json.Marshal(changed)
	c := rawClient(t, f.clientTLS)
	for _, tc := range []struct{ path, body, media string }{
		{protocol.RenewalPath, strings.Replace(string(valid), `"version":1`, `"version":1,"agent_id":"chosen"`, 1), "application/json"},
		{protocol.RenewalPath, string(badCSR), "application/json"},
		{protocol.RenewalPath + "?x=1", string(valid), "application/json"},
		{protocol.RenewalPath, strings.Repeat(" ", protocol.MaxRenewalBytes) + string(valid), "application/json"},
		{protocol.RenewalPath, string(valid), "text/plain"},
	} {
		resp, err := c.Post(url+tc.path, tc.media, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal("invalid renewal accepted", resp.StatusCode)
		}
	}
	credentials, err := f.store.Credentials(t.Context(), f.node.AgentID)
	if err != nil || len(credentials) != 1 {
		t.Fatal("invalid requests issued credentials", err)
	}
	unauth, err := tlsconfig.EnrollmentClient(f.ca, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := rawClient(t, unauth).Post(url+protocol.RenewalPath, "application/json", bytes.NewReader(valid)); err == nil {
		resp.Body.Close()
		t.Fatal("renewal accepted without mTLS")
	}
	resp, err := rawClient(t, unauth).Post(f.enrollURL+protocol.RenewalPath, "application/json", bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("renewal exposed on enrollment listener")
	}
	resp, err = c.Post(f.probeURL+protocol.RenewalPath, "application/json", bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("renewal enabled without explicit handler")
	}
}

func TestRenewalClientRejectsMaliciousResponseWithoutCompletion(t *testing.T) {
	for _, kind := range []string{"node", "epoch", "request", "old_certificate", "key", "root", "path", "policy", "overlap"} {
		t.Run(kind, func(t *testing.T) {
			f := setupEnrollment(t)
			f.enroll(t)
			url := renewalServer(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(io.LimitReader(r.Body, protocol.MaxRenewalBytes+1))
				req, der, err := protocol.DecodeRenewalRequest(data)
				if err != nil {
					t.Error(err)
					return
				}
				csr, err := enrollment.ParseCSR(der)
				if err != nil {
					t.Error(err)
					return
				}
				if kind == "key" {
					_, key, _ := ed25519.GenerateKey(rand.Reader)
					der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
					csr, _ = enrollment.ParseCSR(der)
				}
				chain, _, err := f.issuer.Issue(csr, f.node)
				if err != nil {
					t.Error(err)
					return
				}
				response := map[string]any{"version": 1, "renewal_id": req.RenewalID, "agent_id": f.node.AgentID, "enrollment_epoch": f.node.EnrollmentEpoch, "generation": 2, "previous_certificate_sha256": identity.Fingerprint(f.clientTLS.Certificates[0].Leaf), "previous_valid_until": time.Now().Add(time.Hour).Unix(), "certificate_pem": string(chain)}
				switch kind {
				case "node":
					response["agent_id"] = identity.RandomID()
				case "epoch":
					response["enrollment_epoch"] = identity.RandomID()
				case "request":
					response["renewal_id"] = identity.RandomID()
				case "old_certificate":
					response["previous_certificate_sha256"] = strings.Repeat("0", 64)
				case "root":
					response["root_ca"] = "untrusted"
				case "path":
					response["path"] = "/etc/argus-c2/policy.json"
				case "policy":
					response["policy"] = map[string]bool{"allow": true}
				case "overlap":
					response["previous_valid_until"] = time.Now().Add(48 * time.Hour).Unix()
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}), f.store)
			stage := filepath.Join(f.root, "renewal")
			files := renewalFiles(f, filepath.Join(f.root, "probe"))
			if err := agent.PrepareRenewal(url, files, f.node, stage); err != nil {
				t.Fatal(err)
			}
			if _, err := agent.RequestRenewal(t.Context(), url, files, f.node, stage); err == nil {
				t.Fatal("malicious response accepted")
			}
			for _, name := range []string{"probe-cert.pem", "identity.json"} {
				if _, err := os.Stat(filepath.Join(stage, name)); !os.IsNotExist(err) {
					t.Fatal("unverified output installed", name, err)
				}
			}
		})
	}
}
