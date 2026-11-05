package api

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestNodeMiddlewareValidatesTransportIdentityAndProtocolWithoutDatabase(t *testing.T) {
	c := &x509.Certificate{URIs: []*url.URL{identity.URI("node")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for _, kind := range []string{"valid", "no-tls", "unverified", "no-peer", "bad-identity", "bad-version", "bad-build"} {
		t.Run(kind, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://server/v1/agent/poll", nil)
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}, VerifiedChains: [][]*x509.Certificate{{c}}}
			r.Header.Set(protocol.VersionHeader, strconv.Itoa(protocol.Version))
			r.Header.Set(protocol.AgentVersionHeader, "development")
			switch kind {
			case "no-tls":
				r.TLS = nil
			case "unverified":
				r.TLS.VerifiedChains = nil
			case "no-peer":
				r.TLS.PeerCertificates = nil
			case "bad-identity":
				r.TLS.PeerCertificates = []*x509.Certificate{{}}
			case "bad-version":
				r.Header.Set(protocol.VersionHeader, "999")
			case "bad-build":
				r.Header.Set(protocol.AgentVersionHeader, "")
			}
			called := false
			// A nil Store ensures middleware cannot accidentally add a DB query.
			s := &Server{}
			w := httptest.NewRecorder()
			s.node(func(w http.ResponseWriter, r *http.Request, got *x509.Certificate) {
				called = true
				if got != c {
					t.Fatal("identity changed")
				}
				w.WriteHeader(204)
			})(w, r)
			if called != (kind == "valid") {
				t.Fatal(kind, w.Code, called)
			}
			if !called && w.Code != 401 && w.Code != 426 && w.Code != 400 {
				t.Fatal(w.Code)
			}
		})
	}
}
