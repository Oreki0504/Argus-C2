package enrollment

import (
	"crypto/tls"
	"encoding/json"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const Path = "/api/v1/enroll"

// Handler has a fixed concurrency ceiling and a process-wide request budget.
// Failed attempts never return a token, CSR, key, or database error to clients.
func Handler(store *state.Store, issuer *Issuer) http.Handler {
	slots := make(chan struct{}, 4)
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
		if store == nil || issuer == nil {
			fail(503, "unavailable")
			return
		}
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			fail(401, "unauthorized")
			return
		}
		if r.URL.Path != Path || r.URL.RawPath != "" {
			fail(404, "not_found")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			fail(405, "method_not_allowed")
			return
		}
		mu.Lock()
		now := time.Now()
		if now.Sub(window) >= time.Minute {
			window = now
			count = 0
		}
		allowed := count < 30
		if allowed {
			count++
		}
		mu.Unlock()
		if !allowed {
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
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength <= 0 || r.ContentLength > protocol.MaxEnrollmentBytes || len(r.TransferEncoding) != 0 {
			fail(400, "invalid_request")
			return
		}
		data, err := strictjson.Read(r.Body, protocol.MaxEnrollmentBytes)
		if err != nil {
			fail(400, "invalid_request")
			return
		}
		req, der, err := protocol.DecodeEnrollmentRequest(data)
		if err != nil {
			fail(400, "invalid_request")
			return
		}
		csr, err := ParseCSR(der)
		if err != nil {
			fail(400, "invalid_request")
			return
		}
		node := identity.New()
		chain, cert, err := issuer.Issue(csr, node)
		if err != nil {
			fail(503, "unavailable")
			return
		}
		registration := identity.Registration{AgentID: node.AgentID, EnrollmentEpoch: node.EnrollmentEpoch, CertificateSHA256: identity.Fingerprint(cert), Enabled: true}
		if err := store.RegisterFrom(r.Context(), req.Token, registration, audit.Peer(r.RemoteAddr)); err != nil {
			fail(403, "enrollment_rejected")
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(protocol.EnrollmentResponse{Version: protocol.Version, AgentID: node.AgentID, EnrollmentEpoch: node.EnrollmentEpoch, CertificatePEM: string(chain)})
	})
}
