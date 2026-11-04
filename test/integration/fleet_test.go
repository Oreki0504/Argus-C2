package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/api"
	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type fleet struct {
	t                     *testing.T
	dir                   string
	store                 *database.Store
	issuer                *enrollment.Issuer
	admins                auth.Config
	adminToken, readToken string
	server                *httptest.Server
	client                *http.Client
	url                   string
}

func newFleet(t *testing.T) *fleet {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fleet")
	if e := enrollment.Initialize(dir, []string{"127.0.0.1", "localhost"}); e != nil {
		t.Fatal(e)
	}
	store, e := database.Open(filepath.Join(dir, "state"), true)
	if e != nil {
		t.Fatal(e)
	}
	issuer, e := enrollment.Load(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	admin, token, e := auth.NewUser("admin", "Admin")
	if e != nil {
		t.Fatal(e)
	}
	reader, read, e := auth.NewUser("reader", "ReadOnly")
	if e != nil {
		t.Fatal(e)
	}
	f := &fleet{t: t, dir: dir, store: store, issuer: issuer, admins: auth.Config{Users: []auth.User{admin, reader}}, adminToken: token, readToken: read}
	f.start("")
	f.client, e = transport.Client(filepath.Join(dir, "ca.pem"), "", "")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.client.CloseIdleConnections(); f.server.Close(); f.store.Close() })
	return f
}
func (f *fleet) start(address string) {
	f.t.Helper()
	cfg, e := transport.Server(filepath.Join(f.dir, "server.pem"), filepath.Join(f.dir, "server-key.pem"), filepath.Join(f.dir, "ca.pem"))
	if e != nil {
		f.t.Fatal(e)
	}
	s := httptest.NewUnstartedServer((&api.Server{Store: f.store, Enrollment: enrollment.Service{Store: f.store, Issuer: f.issuer}, Admins: f.admins}).Handler())
	if address != "" {
		s.Listener.Close()
		s.Listener, e = net.Listen("tcp", address)
		if e != nil {
			f.t.Fatal(e)
		}
	}
	s.TLS = cfg
	s.StartTLS()
	f.server = s
	f.url = s.URL
}
func (f *fleet) call(token, method, path string, input any) []byte {
	f.t.Helper()
	b, e := transport.Request(f.t.Context(), f.client, f.url, token, method, path, input)
	if e != nil {
		f.t.Fatal(path, e)
	}
	return b
}
func (f *fleet) enroll(name string, p policy.Policy) *agent.Runner {
	f.t.Helper()
	token, e := f.store.CreateToken(f.t.Context(), "admin", time.Minute)
	if e != nil {
		f.t.Fatal(e)
	}
	dir := filepath.Join(f.dir, name)
	ca := filepath.Join(f.dir, "ca.pem")
	if e = agent.Enroll(f.t.Context(), f.url, ca, dir, token, name); e != nil {
		f.t.Fatal(e)
	}
	r, e := agent.Open(f.url, ca, dir, p)
	if e != nil {
		f.t.Fatal(e)
	}
	f.t.Cleanup(func() { r.Close() })
	return r
}
func (f *fleet) task(node string, kind protocol.TaskType, params string) protocol.Task {
	f.t.Helper()
	b := f.call(f.adminToken, "POST", "/v1/tasks", protocol.TaskRequest{NodeID: node, Type: kind, Params: json.RawMessage(params), TTLSeconds: 60, ExecutionTimeoutMS: 10000})
	var t protocol.Task
	if e := json.Unmarshal(b, &t); e != nil {
		f.t.Fatal(e)
	}
	return t
}
func wantStatus(t *testing.T, e error, status int) {
	t.Helper()
	var api *transport.APIError
	if !errors.As(e, &api) || api.Status != status {
		t.Fatalf("got %v; want HTTP %d", e, status)
	}
}
func TestFiveNodeDiagnosticsAndAuthorization(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux fleet collector integration; transport tests run on all platforms")
	}
	f := newFleet(t)
	p := policy.Default()
	p.Telemetry.SampleMilliseconds = 100
	p.Allowed = append(p.Allowed, protocol.ServiceStatus, protocol.ProcessList, protocol.NetworkListeners)
	p.Services = []resources.Service{{ID: "journal", Unit: "systemd-journald.service"}}
	sshDir := filepath.Join(f.dir, "ssh")
	if e := os.Mkdir(sshDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(sshDir, "sshd_config"), []byte("PermitRootLogin no\nPasswordAuthentication no\n"), 0600); e != nil {
		t.Fatal(e)
	}
	p.Allowed = append(p.Allowed, protocol.SSHAudit)
	p.SSHProfiles = []resources.SSHProfile{{ID: "host", Files: []resources.SSHFile{{ID: "config", Kind: "sshd_config", BaseDir: sshDir, RelativePath: "sshd_config", OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()), MaxBytes: 4096}}}}
	ids := map[string]bool{}
	for _, name := range []string{"one", "two", "three", "four", "five"} {
		r := f.enroll(name, p)
		id := r.Engine.State.NodeID
		if ids[id] {
			t.Fatal("shared node identity")
		}
		ids[id] = true
		for _, kind := range []protocol.TaskType{protocol.SystemInfo, protocol.SystemMetrics, protocol.ServiceStatus, protocol.ProcessList, protocol.NetworkListeners, protocol.SSHAudit} {
			params := "{}"
			if kind == protocol.ServiceStatus {
				params = `{"service_id":"journal"}`
			}
			if kind == protocol.SSHAudit {
				params = `{"profile_id":"host"}`
			}
			job := f.task(id, kind, params)
			if e := r.Step(t.Context()); e != nil {
				t.Fatal(e)
			}
			view, e := f.store.Task(t.Context(), job.ID)
			if e != nil || view.Task.Status != protocol.Succeeded || view.Result == nil {
				t.Fatal(view, e)
			}
			if e = view.Result.CheckAssignment(view.Task); e != nil {
				t.Fatal(e)
			}
		}
	}
	var nodes []protocol.Node
	if e := json.Unmarshal(f.call(f.readToken, "GET", "/v1/nodes", nil), &nodes); e != nil || len(nodes) != 5 {
		t.Fatal(nodes, e)
	}
	for _, n := range nodes {
		if n.LastSeenAt == 0 || n.CertificateFingerprint == "" {
			t.Fatal("missing health", n)
		}
	}
	request := protocol.TaskRequest{NodeID: nodes[0].ID, Type: protocol.SystemInfo, Params: json.RawMessage(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 10000}
	for _, token := range []string{"", strings.Repeat("x", 50), f.readToken} {
		_, e := transport.Request(t.Context(), f.client, f.url, token, "POST", "/v1/tasks", request)
		status := 401
		if token == f.readToken {
			status = 403
		}
		wantStatus(t, e, status)
	}
	_, e := transport.Request(t.Context(), f.client, f.url, f.adminToken, "POST", "/v1/agent/poll", struct{}{})
	wantStatus(t, e, 401)
	events, e := f.store.AuditEvents(t.Context(), 0)
	if e != nil || len(events) < 75 {
		t.Fatal("audit events missing", len(events), e)
	}
	raw, _ := json.Marshal(events)
	if bytes.Contains(raw, []byte(f.adminToken)) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("audit leaked secret")
	}
}
func TestServerRestartOutageAndLateResultRecovery(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
	b, e := transport.Request(t.Context(), r.Client, f.url, "", "POST", "/v1/agent/poll", struct{}{})
	if e != nil {
		t.Fatal(e)
	}
	duplicate, e := transport.Request(t.Context(), r.Client, f.url, "", "POST", "/v1/agent/poll", struct{}{})
	if e != nil || !bytes.Equal(b, duplicate) {
		t.Fatal("poll redelivery changed task", e)
	}
	delivered, e := protocol.DecodeTask(b)
	if e != nil {
		t.Fatal(e)
	}
	_, e = r.Engine.Process(t.Context(), delivered, func(ctx context.Context, id string) error {
		_, e := transport.Request(ctx, r.Client, f.url, "", "POST", "/v1/agent/tasks/"+id+"/running", struct{}{})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	// Simulate server outage after execution but before result delivery.
	address := f.server.Listener.Addr().String()
	f.server.Close()
	if e = r.Step(t.Context()); e == nil {
		t.Fatal("outage hidden")
	}
	pending, e := r.Engine.State.Pending(t.Context())
	if e != nil || len(pending) != 1 {
		t.Fatal("pending result lost", e)
	}
	f.store.Close()
	f.store, e = database.Open(filepath.Join(f.dir, "state"), false)
	if e != nil {
		t.Fatal(e)
	}
	f.start(address)
	if e = r.Step(t.Context()); e != nil {
		t.Fatal("reconnection failed", e)
	}
	view, e := f.store.Task(t.Context(), job.ID)
	if e != nil || view.Result == nil || view.Task.Status != protocol.Succeeded {
		t.Fatal(view, e)
	}
	// Duplicate result remains idempotent; a contradictory terminal result fails.
	_, e = transport.Request(t.Context(), r.Client, f.url, "", "POST", "/v1/agent/results", view.Result)
	if e != nil {
		t.Fatal(e)
	}
	changed := *view.Result
	changed.Status = protocol.Failed
	changed.Payload = json.RawMessage(`{}`)
	changed.Error = "different"
	_, e = transport.Request(t.Context(), r.Client, f.url, "", "POST", "/v1/agent/results", changed)
	wantStatus(t, e, 409)
	backupDir := filepath.Join(f.dir, "backup")
	if e = os.Mkdir(backupDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = f.store.Backup(t.Context(), filepath.Join(backupDir, "argus.db")); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(backupDir, "argus.db"), 0600); e != nil {
		t.Fatal(e)
	}
	restored, e := database.Open(backupDir, false)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	recovered, e := restored.Task(t.Context(), job.ID)
	if e != nil || recovered.Task.Status != protocol.Succeeded {
		t.Fatal("backup lost committed result", e)
	}
}
func TestLocalPolicyRevocationAndRequestLimits(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job := f.task(r.Engine.State.NodeID, protocol.ServiceStatus, `{"service_id":"journal"}`)
	if e := r.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	v, e := f.store.Task(t.Context(), job.ID)
	if e != nil || v.Result == nil || v.Result.Error != "local_policy_denied" {
		t.Fatal(v, e)
	}
	// Keep pooled mTLS connection established while disabling the node.
	f.call(f.adminToken, "POST", "/v1/nodes/"+r.Engine.State.NodeID+"/disable", struct{}{})
	e = r.Step(t.Context())
	wantStatus(t, e, 401)
	for _, body := range []string{`{"node_id":"x","task_type":"shell","parameters":{},"ttl_seconds":60}`, `{"node_id":"x","task_type":"system.info","parameters":{"command":"id"},"ttl_seconds":60}`, strings.Repeat(" ", protocol.MaxPayloadBytes+1)} {
		req, e := http.NewRequestWithContext(t.Context(), "POST", f.url+"/v1/tasks", strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Bearer "+f.adminToken)
		req.Header.Set("Content-Type", "application/json")
		res, e := f.client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 400 {
			t.Fatalf("invalid request returned %d", res.StatusCode)
		}
	}
}
func TestEnrollmentRetryRenewalAndExpiredCertificate(t *testing.T) {
	f := newFleet(t)
	token, e := f.store.CreateToken(t.Context(), "admin", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := enrollment.CSR(key)
	if e != nil {
		t.Fatal(e)
	}
	f.issuer.Lifetime = 2 * time.Hour
	request := protocol.EnrollmentRequest{Token: token, Hostname: "host", CSR: csr}
	first := f.call("", "POST", "/v1/enroll", request)
	second := f.call("", "POST", "/v1/enroll", request)
	if !bytes.Equal(first, second) {
		t.Fatal("enrollment retry changed identity")
	}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCSR, _ := enrollment.CSR(otherKey)
	_, e = transport.Request(t.Context(), f.client, f.url, "", "POST", "/v1/enroll", protocol.EnrollmentRequest{Token: token, Hostname: "other", CSR: otherCSR})
	wantStatus(t, e, 401)
	var response protocol.EnrollmentResponse
	if e = json.Unmarshal(first, &response); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(f.dir, "renewal")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	keyPEM, e := enrollment.KeyPEM(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "agent-key.pem"), keyPEM, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "agent.pem"), []byte(response.Certificate), 0600); e != nil {
		t.Fatal(e)
	}
	state, e := agent.OpenState(dir, response.NodeID, true)
	if e != nil {
		t.Fatal(e)
	}
	state.Close()
	oldClient, e := transport.Client(filepath.Join(f.dir, "ca.pem"), filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	defer oldClient.CloseIdleConnections()
	_, e = transport.Request(t.Context(), oldClient, f.url, "", "POST", "/v1/agent/renew", protocol.RenewalRequest{CSR: otherCSR})
	var renewalError *transport.APIError
	if !errors.As(e, &renewalError) || renewalError.Status != 400 || renewalError.Code != "renewal_key_mismatch" {
		t.Fatal("changed-key renewal not classified", e)
	}
	var unchanged string
	if e = f.store.DB.QueryRow("SELECT certificate FROM nodes WHERE id=?", response.NodeID).Scan(&unchanged); e != nil || unchanged != response.Certificate {
		t.Fatal("rejected renewal changed identity", e)
	}
	r, e := agent.Open(f.url, filepath.Join(f.dir, "ca.pem"), dir, policy.Default())
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	f.issuer.Lifetime = 30 * 24 * time.Hour
	if e = r.Renew(t.Context()); e != nil {
		t.Fatal(e)
	}
	newPair, e := transport.Pair(filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	newCert, e := x509.ParseCertificate(newPair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	if time.Until(newCert.NotAfter) < 29*24*time.Hour {
		t.Fatal("certificate not renewed")
	}
	retried, e := transport.Request(t.Context(), oldClient, f.url, "", "POST", "/v1/agent/renew", protocol.RenewalRequest{CSR: csr})
	if e != nil {
		t.Fatal("lost renewal response unrecoverable", e)
	}
	var again protocol.EnrollmentResponse
	if e = json.Unmarshal(retried, &again); e != nil || again.NodeID != response.NodeID {
		t.Fatal(e)
	}
	stored, e := os.ReadFile(filepath.Join(dir, "agent.pem"))
	if e != nil || again.Certificate != string(stored) {
		t.Fatal("renewal retry issued another generation", e)
	}
	expired := *newCert
	expired.NotAfter = time.Now().Add(-time.Second)
	if _, e = f.store.Authorize(t.Context(), &expired); !errors.Is(e, database.ErrUnauthorized) {
		t.Fatal("expired certificate accepted on existing connection", e)
	}
	if id, e := identity.FromCertificate(newCert); e != nil || id != response.NodeID {
		t.Fatal("identity changed", e)
	}
}

func TestUntrustedServerAndExpiredTLSIdentity(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	other := newFleet(t)
	wrongCA, e := transport.Client(filepath.Join(other.dir, "ca.pem"), "", "")
	if e != nil {
		t.Fatal(e)
	}
	defer wrongCA.CloseIdleConnections()
	if _, e = transport.Request(t.Context(), wrongCA, f.url, f.adminToken, "GET", "/v1/health", nil); e == nil {
		t.Fatal("untrusted server certificate accepted")
	}
	wrongName, e := transport.Client(filepath.Join(f.dir, "ca.pem"), "", "")
	if e != nil {
		t.Fatal(e)
	}
	defer wrongName.CloseIdleConnections()
	wrongName.Transport.(*http.Transport).TLSClientConfig.ServerName = "wrong.example"
	if _, e = transport.Request(t.Context(), wrongName, f.url, f.adminToken, "GET", "/v1/health", nil); e == nil {
		t.Fatal("wrong hostname accepted")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(123), NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI(r.Engine.State.NodeID)}}
	der, e := x509.CreateCertificate(rand.Reader, template, f.issuer.Certificate, &key.PublicKey, f.issuer.Key)
	if e != nil {
		t.Fatal(e)
	}
	keyBytes, e := enrollment.KeyPEM(key)
	if e != nil {
		t.Fatal(e)
	}
	certFile, keyFile := filepath.Join(f.dir, "expired.pem"), filepath.Join(f.dir, "expired-key.pem")
	if e = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyFile, keyBytes, 0600); e != nil {
		t.Fatal(e)
	}
	expired, e := transport.Client(filepath.Join(f.dir, "ca.pem"), certFile, keyFile)
	if e != nil {
		t.Fatal(e)
	}
	defer expired.CloseIdleConnections()
	if _, e = transport.Request(t.Context(), expired, f.url, "", "POST", "/v1/agent/poll", struct{}{}); e == nil {
		t.Fatal("expired certificate passed TLS handshake")
	}
	// Offline maintenance must remain available after expiry, but still takes
	// the process lock and validates the certificate/key pair and node binding.
	job, _ := pendingResult(t, f, r)
	if local, e := agent.OpenLocal(r.Dir); e == nil {
		local.Close()
		t.Fatal("maintenance bypassed active worker lock")
	}
	r.Close()
	if e = os.WriteFile(filepath.Join(r.Dir, "agent.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(r.Dir, "agent-key.pem"), keyBytes, 0600); e != nil {
		t.Fatal(e)
	}
	if online, e := agent.Open(f.url, r.CA, r.Dir, policy.Default()); e == nil {
		online.Close()
		t.Fatal("expired identity accepted for online work")
	}
	local, e := agent.OpenLocal(r.Dir)
	if e != nil {
		t.Fatal("expired certificate blocked offline maintenance", e)
	}
	defer local.Close()
	if b, e := local.ResultBytes(t.Context(), job.ID); e != nil || len(b) == 0 {
		t.Fatal("retained result unavailable offline", e)
	}
}
