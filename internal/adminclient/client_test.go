package adminclient

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/management"
)

func TestClientRejectsRedirectsOversizeAndUntrustedTLS(t *testing.T) {
	for _, scenario := range []string{"redirect", "oversize", "encoding", "untrusted", "hostname"} {
		t.Run(scenario, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "redirect":
					w.Header().Set("Location", "/api/v1/second")
					w.WriteHeader(302)
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat(" ", management.MaxResponseBytes+1)))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write([]byte(`{}`))
				default:
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer s.Close()
			roots := x509.NewCertPool()
			if scenario != "untrusted" {
				roots.AddCert(s.Certificate())
			}
			name := "127.0.0.1"
			if scenario == "hostname" {
				name = "wrong.invalid"
			}
			c := newClient(s.URL, "test", &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name})
			defer c.Close()
			if _, err := c.Request(t.Context(), strings.Repeat("a", 64), "GET", "/api/v1/agents", nil); err == nil {
				t.Fatal("unsafe response accepted")
			}
			if scenario == "redirect" && calls.Load() != 1 {
				t.Fatal("redirect forwarded credentials")
			}
			if (scenario == "hostname" || scenario == "untrusted") && calls.Load() != 0 {
				t.Fatal("request crossed unverified TLS")
			}
		})
	}
}
