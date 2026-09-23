package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

type fixture struct {
	b                          *devpki.Bundle
	r                          *identity.Registry
	serverConfig, clientConfig *tls.Config
}

func setup(t *testing.T) *fixture {
	t.Helper()
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "pki")
	if err := b.WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	r, err := identity.LoadRegistry(filepath.Join(dir, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	node, err := identity.LoadNode(filepath.Join(dir, "identity.json"))
	if err != nil || node != b.Node {
		t.Fatal("identity file mismatch", err)
	}
	sc, err := tlsconfig.Server(tlsconfig.Files{Certificate: filepath.Join(dir, "server-cert.pem"), PrivateKey: filepath.Join(dir, "server-key.pem"), CA: filepath.Join(dir, "ca.pem")}, r)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := tlsconfig.Client(tlsconfig.Files{Certificate: filepath.Join(dir, "probe-cert.pem"), PrivateKey: filepath.Join(dir, "probe-key.pem"), CA: filepath.Join(dir, "ca.pem")}, node, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{b: b, r: r, serverConfig: sc, clientConfig: cc}
}
func start(t *testing.T, config *tls.Config, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.TLS = config.Clone()
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func rawClient(t *testing.T, config *tls.Config) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: config.Clone(), Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func TestAuthenticatedConnection(t *testing.T) {
	f := setup(t)
	s := start(t, f.serverConfig, server.Handler(f.r))
	// Proxy environment must not redirect a probe connection.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	c, err := agent.NewClient(s.URL, f.clientConfig, f.b.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	info, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 1 || info.AgentID != f.b.Node.AgentID || info.EnrollmentEpoch != f.b.Node.EnrollmentEpoch {
		t.Fatal("wrong identity response")
	}
	response, err := rawClient(t, f.clientConfig).Get(s.URL + server.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.TLS.Version != tls.VersionTLS13 {
		t.Fatal("TLS 1.3 was not negotiated")
	}
}

func TestClientCertificateRejection(t *testing.T) {
	for _, kind := range []string{"missing", "unknown CA", "expired", "future", "wrong usage", "unregistered node", "replacement certificate", "wrong epoch", "invalid SAN", "disabled", "TLS 1.2"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			config := f.clientConfig.Clone()
			template, _ := devpki.ClientTemplate(f.b.Node)
			ca := f.b.CA
			switch kind {
			case "missing":
				config.Certificates = nil
			case "unknown CA":
				var err error
				ca, err = devpki.NewAuthority()
				if err != nil {
					t.Fatal(err)
				}
			case "expired":
				template.NotBefore = time.Now().Add(-2 * time.Hour)
				template.NotAfter = time.Now().Add(-time.Hour)
			case "future":
				template.NotBefore = time.Now().Add(time.Hour)
				template.NotAfter = time.Now().Add(2 * time.Hour)
			case "wrong usage":
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "unregistered node":
				template, _ = devpki.ClientTemplate(identity.New())
			case "replacement certificate": // Same identity and CA, different key/certificate.
			case "wrong epoch":
				node := f.b.Node
				node.EnrollmentEpoch = identity.RandomID()
				template, _ = devpki.ClientTemplate(node)
			case "invalid SAN":
				u, _ := url.Parse("argus://nodes/invalid")
				template.URIs = []*url.URL{u}
			case "disabled":
				f.r.Disable(f.b.Node.AgentID)
			case "TLS 1.2":
				config.MinVersion = tls.VersionTLS12
				config.MaxVersion = tls.VersionTLS12
			}
			if kind != "missing" && kind != "disabled" && kind != "TLS 1.2" {
				cert, err := ca.Issue(template)
				if err != nil {
					t.Fatal(err)
				}
				config.Certificates = []tls.Certificate{cert.TLS}
				// Register invalid certs where necessary so PKI/SAN checks, not
				// just fingerprint mismatch, must reject them.
				if kind == "expired" || kind == "future" || kind == "wrong usage" || kind == "unknown CA" || kind == "invalid SAN" {
					record := f.b.Registration()
					record.CertificateSHA256 = identity.Fingerprint(cert.Leaf)
					f.r, err = identity.NewRegistry([]identity.Registration{record})
					if err != nil {
						t.Fatal(err)
					}
					// Preserve normal X.509 checks while using this fixture registry.
					f.serverConfig.VerifyConnection = func(state tls.ConnectionState) error { _, err := f.r.Authorize(state.PeerCertificates[0]); return err }
				}
			}
			s := start(t, f.serverConfig, server.Handler(f.r))
			resp, err := rawClient(t, config).Get(s.URL + server.IdentityPath)
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil {
				t.Fatal("invalid peer completed TLS request")
			}
		})
	}
}

func TestServerCertificateRejection(t *testing.T) {
	for _, kind := range []string{"wrong hostname", "expired", "unknown CA", "wrong usage"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			template := devpki.ServerTemplate()
			ca := f.b.CA
			switch kind {
			case "wrong hostname":
				template.IPAddresses = nil
				template.DNSNames = []string{"wrong.example"}
			case "expired":
				template.NotBefore = time.Now().Add(-2 * time.Hour)
				template.NotAfter = time.Now().Add(-time.Hour)
			case "unknown CA":
				var err error
				ca, err = devpki.NewAuthority()
				if err != nil {
					t.Fatal(err)
				}
			case "wrong usage":
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			cert, err := ca.Issue(template)
			if err != nil {
				t.Fatal(err)
			}
			config := f.serverConfig.Clone()
			config.Certificates = []tls.Certificate{cert.TLS}
			s := start(t, config, server.Handler(f.r))
			c, err := agent.NewClient(s.URL, f.clientConfig, f.b.Node)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Connect(context.Background()); err == nil {
				t.Fatal("accepted invalid server certificate")
			}
		})
	}
}

func TestDisableOnEstablishedConnection(t *testing.T) {
	f := setup(t)
	s := start(t, f.serverConfig, server.Handler(f.r))
	c := rawClient(t, f.clientConfig)
	resp, err := c.Get(s.URL + server.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("initial authorization failed")
	}
	f.r.Disable(f.b.Node.AgentID)
	var reused atomic.Bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+server.IdentityPath, nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !reused.Load() {
		t.Fatal("test did not exercise an established connection")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("disabled node retained access on a warm connection")
	}
}

func TestEndpointBoundaries(t *testing.T) {
	f := setup(t)
	s := start(t, f.serverConfig, server.Handler(f.r))
	c := rawClient(t, f.clientConfig)
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/api/v1/tasks", "", 404}, {"POST", server.IdentityPath, "", 405},
		{"GET", server.IdentityPath + "?agent_id=another", "", 400}, {"GET", server.IdentityPath, "{}", 400},
	} {
		req, _ := http.NewRequest(tc.method, s.URL+tc.path, strings.NewReader(tc.body))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s %s: %d", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestProbeRejectsUntrustedResponses(t *testing.T) {
	for _, kind := range []string{"redirect", "oversized", "wrong identity", "unknown field", "invalid type"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			var targetCalls atomic.Int32
			s := start(t, f.serverConfig, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect-target" {
					targetCalls.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "redirect":
					http.Redirect(w, r, "/redirect-target", http.StatusTemporaryRedirect)
				case "oversized":
					_, _ = io.WriteString(w, strings.Repeat(" ", 4097))
				case "wrong identity":
					_ = json.NewEncoder(w).Encode(protocol.ConnectionInfo{Version: 1, AgentID: identity.RandomID(), EnrollmentEpoch: f.b.Node.EnrollmentEpoch})
				case "unknown field":
					_, _ = io.WriteString(w, `{"version":1,"agent_id":"`+f.b.Node.AgentID+`","enrollment_epoch":"`+f.b.Node.EnrollmentEpoch+`","extra":true}`)
				case "invalid type":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = io.WriteString(w, "unexpected")
				}
			}))
			c, err := agent.NewClient(s.URL, f.clientConfig, f.b.Node)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Connect(context.Background()); err == nil {
				t.Fatal("accepted untrusted response")
			}
			if targetCalls.Load() != 0 {
				t.Fatal("probe followed a redirect")
			}
		})
	}
}
