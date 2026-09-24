package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/collector"
	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

type enrollmentFixture struct {
	store                         *state.Store
	issuer                        *enrollment.Issuer
	root, ca, enrollURL, probeURL string
	enrollTLS, clientTLS          *tls.Config
	node                          identity.Node
}

func setupEnrollment(t *testing.T) *enrollmentFixture {
	t.Helper()
	root := t.TempDir()
	pki := filepath.Join(root, "pki")
	b, err := devpki.NewEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.WriteDir(pki); err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(filepath.Join(root, "server"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ca := filepath.Join(pki, "ca.pem")
	issuer, err := enrollment.LoadIssuer(filepath.Join(pki, "issuer-cert.pem"), filepath.Join(pki, "issuer-key.pem"), ca)
	if err != nil {
		t.Fatal(err)
	}
	files := tlsconfig.Files{Certificate: filepath.Join(pki, "server-cert.pem"), PrivateKey: filepath.Join(pki, "server-key.pem"), CA: ca}
	et, err := tlsconfig.EnrollmentServer(files)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := tlsconfig.Server(files, s)
	if err != nil {
		t.Fatal(err)
	}
	es := start(t, et, enrollment.Handler(s, issuer))
	ps := start(t, pt, server.Handler(s, s))
	return &enrollmentFixture{store: s, issuer: issuer, root: root, ca: ca, enrollURL: es.URL, probeURL: ps.URL, enrollTLS: et}
}
func (f *enrollmentFixture) enroll(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	token, err := f.store.IssueToken(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.root, "probe")
	f.node, err = agent.Enroll(ctx, f.enrollURL, f.ca, token, dir)
	if err != nil {
		t.Fatal(err)
	}
	f.clientTLS, err = tlsconfig.Client(tlsconfig.Files{Certificate: filepath.Join(dir, "probe-cert.pem"), PrivateKey: filepath.Join(dir, "probe-key.pem"), CA: f.ca}, f.node, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Enroll(ctx, f.enrollURL, f.ca, token, filepath.Join(f.root, "reused")); err == nil {
		t.Fatal("enrollment token reused")
	}
	before, err := os.ReadFile(filepath.Join(dir, "probe-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Enroll(ctx, f.enrollURL, f.ca, token, dir); err == nil {
		t.Fatal("existing probe overwritten")
	}
	after, err := os.ReadFile(filepath.Join(dir, "probe-key.pem"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing probe key changed")
	}
}
func collectHeartbeat(t *testing.T, n identity.Node) protocol.Heartbeat {
	t.Helper()
	h, err := collector.Collect(context.Background(), n, collector.Config{IntervalSeconds: 30, SampleMilliseconds: 100, DiskPaths: []string{"/"}, NetworkInterfaces: []string{"lo"}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestEnrollmentToHeartbeat(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	c, err := agent.NewClient(f.probeURL, f.clientTLS, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := collectHeartbeat(t, f.node)
	if err := c.Heartbeat(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	nodes, err := f.store.Snapshots(context.Background())
	if err != nil || len(nodes) != 1 || nodes[0].ReceivedAt == 0 {
		t.Fatal("heartbeat not stored", err)
	}
	stored, err := protocol.DecodeHeartbeat(nodes[0].Heartbeat)
	if err != nil || stored.AgentID != f.node.AgentID {
		t.Fatal("stored heartbeat mismatch", err)
	}
	unauth, err := tlsconfig.EnrollmentClient(f.ca, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := rawClient(t, unauth).Get(f.probeURL + server.IdentityPath); err == nil {
		resp.Body.Close()
		t.Fatal("enrollment weakened mTLS listener")
	}
}

func TestHeartbeatIdentityAndDisableOnKeepAlive(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	h := collectHeartbeat(t, f.node)
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	c := rawClient(t, f.clientTLS)
	for _, tc := range []struct{ name, path, body, media string }{
		{"cross node", server.HeartbeatPath, strings.Replace(string(data), f.node.AgentID, identity.RandomID(), 1), "application/json"},
		{"cross epoch", server.HeartbeatPath, strings.Replace(string(data), f.node.EnrollmentEpoch, identity.RandomID(), 1), "application/json"},
		{"extra field", server.HeartbeatPath, strings.Replace(string(data), `"version":1`, `"version":1,"callback":"https://example.com"`, 1), "application/json"},
		{"query", server.HeartbeatPath + "?x=1", string(data), "application/json"},
		{"oversized", server.HeartbeatPath, strings.Repeat(" ", protocol.MaxHeartbeatBytes) + string(data), "application/json"},
		{"wrong media", server.HeartbeatPath, string(data), "text/plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := c.Post(f.probeURL+tc.path, tc.media, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != 400 {
				t.Fatalf("unexpected status %d", resp.StatusCode)
			}
		})
	}
	var reused atomic.Bool
	post := func() int {
		req, err := http.NewRequest(http.MethodPost, f.probeURL+server.HeartbeatPath, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if status := post(); status != 200 {
		t.Fatal("valid heartbeat rejected", status)
	}
	if status := post(); status != 429 {
		t.Fatal("heartbeat rate limit absent", status)
	}
	if err := f.store.Disable(context.Background(), f.node.AgentID); err != nil {
		t.Fatal(err)
	}
	if status := post(); status != 401 || !reused.Load() {
		t.Fatal("disabled node retained access on reused connection", status, reused.Load())
	}
}

func TestRejectedCSRDoesNotConsumeToken(t *testing.T) {
	f := setupEnrollment(t)
	token, err := f.store.IssueToken(context.Background(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr[len(csr)-1] ^= 1
	body, err := json.Marshal(protocol.EnrollmentRequest{Version: 1, Token: token, CSR: base64.RawURLEncoding.EncodeToString(csr)})
	if err != nil {
		t.Fatal(err)
	}
	config, err := tlsconfig.EnrollmentClient(f.ca, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rawClient(t, config).Post(f.enrollURL+enrollment.Path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("invalid proof accepted", resp.StatusCode)
	}
	if _, err := agent.Enroll(context.Background(), f.enrollURL, f.ca, token, filepath.Join(f.root, "valid")); err != nil {
		t.Fatal("malformed CSR consumed token", err)
	}
}

func TestEnrollmentClientRejectsMaliciousReplies(t *testing.T) {
	for _, kind := range []string{"redirect", "oversize", "wrong key", "wrong identity", "extra field", "wrong media", "untrusted server"} {
		t.Run(kind, func(t *testing.T) {
			f := setupEnrollment(t)
			var redirects atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/enroll" {
					redirects.Add(1)
					w.WriteHeader(500)
					return
				}
				if kind == "redirect" {
					http.Redirect(w, r, "/unexpected", 307)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if kind == "wrong media" {
					w.Header().Set("Content-Type", "text/plain")
				}
				w.WriteHeader(201)
				if kind == "oversize" {
					io.WriteString(w, strings.Repeat("x", protocol.MaxEnrollmentBytes+1))
					return
				}
				data, err := io.ReadAll(io.LimitReader(r.Body, 8193))
				if err != nil {
					t.Error(err)
					return
				}
				_, der, err := protocol.DecodeEnrollmentRequest(data)
				if err != nil {
					t.Error(err)
					return
				}
				if kind == "wrong key" {
					_, key, e := ed25519.GenerateKey(rand.Reader)
					if e != nil {
						t.Error(e)
						return
					}
					der, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
					if err != nil {
						t.Error(err)
						return
					}
				}
				csr, err := enrollment.ParseCSR(der)
				if err != nil {
					t.Error(err)
					return
				}
				n := identity.New()
				chain, _, err := f.issuer.Issue(csr, n)
				if err != nil {
					t.Error(err)
					return
				}
				if kind == "wrong identity" {
					n = identity.New()
				}
				response := protocol.EnrollmentResponse{Version: 1, AgentID: n.AgentID, EnrollmentEpoch: n.EnrollmentEpoch, CertificatePEM: string(chain)}
				out, err := json.Marshal(response)
				if err != nil {
					t.Error(err)
					return
				}
				if kind == "extra field" {
					out = bytes.Replace(out, []byte(`"version":1`), []byte(`"version":1,"server":"https://example.com"`), 1)
				}
				w.Write(out)
			})
			s := start(t, f.enrollTLS, handler)
			ca := f.ca
			if kind == "untrusted server" {
				b, err := devpki.NewEnrollment()
				if err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(f.root, "other-ca")
				if err := b.WriteDir(dir); err != nil {
					t.Fatal(err)
				}
				ca = filepath.Join(dir, "ca.pem")
			}
			dir := filepath.Join(f.root, "probe")
			if _, err := agent.Enroll(context.Background(), s.URL, ca, strings.Repeat("a", 64), dir); err == nil {
				t.Fatal("malicious enrollment response accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "identity.json")); !os.IsNotExist(err) {
				t.Fatal("failed enrollment marked complete")
			}
			if redirects.Load() != 0 {
				t.Fatal("enrollment followed redirect")
			}
		})
	}
}
