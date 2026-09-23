package server

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
)

func TestLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8443", "[::1]:8443"} {
		if err := LoopbackAddress(addr); err != nil {
			t.Fatal(err)
		}
	}
	for _, addr := range []string{":8443", "0.0.0.0:8443", "[::]:8443", "192.0.2.1:8443", "localhost:8443", "invalid"} {
		if LoopbackAddress(addr) == nil {
			t.Fatalf("accepted nonliteral loopback address %s", addr)
		}
	}
}
func TestNoPlaintextAccess(t *testing.T) {
	w := httptest.NewRecorder()
	Handler(nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, IdentityPath, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("plaintext request gained access")
	}
}

func TestPreviouslyVerifiedChainExpires(t *testing.T) {
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := identity.NewRegistry([]identity.Registration{b.Registration()})
	if err != nil {
		t.Fatal(err)
	}
	for _, future := range []bool{false, true} {
		ca := *b.CA.Certificate
		if future {
			ca.NotBefore = time.Now().Add(time.Hour)
		} else {
			ca.NotAfter = time.Now().Add(-time.Second)
		}
		r := httptest.NewRequest(http.MethodGet, IdentityPath, nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{b.Probe.Leaf}, VerifiedChains: [][]*x509.Certificate{{b.Probe.Leaf, &ca}}}
		w := httptest.NewRecorder()
		Handler(registry).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("accepted a stale chain on an established connection")
		}
	}
}
