package enrollment

import (
	"encoding/json"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

// RenewalHandler is mounted only inside the mTLS probe handler. It also
// verifies its own preconditions so mounting it elsewhere cannot remove mTLS.
func RenewalHandler(store *state.Store, issuer *Issuer) http.Handler {
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
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) < 2 || len(r.TLS.PeerCertificates) == 0 {
			fail(401, "unauthorized")
			return
		}
		now := time.Now()
		for _, cert := range r.TLS.VerifiedChains[0] {
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				fail(401, "unauthorized")
				return
			}
		}
		old := r.TLS.PeerCertificates[0]
		if _, err := store.Authorize(old); err != nil {
			fail(401, "unauthorized")
			return
		}
		if r.URL.Path != protocol.RenewalPath || r.URL.RawPath != "" {
			fail(404, "not_found")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			fail(405, "method_not_allowed")
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength <= 0 || r.ContentLength > protocol.MaxRenewalBytes || len(r.TransferEncoding) != 0 {
			fail(400, "invalid_request")
			return
		}
		mu.Lock()
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
		data, err := strictjson.Read(r.Body, protocol.MaxRenewalBytes)
		if err != nil {
			fail(400, "invalid_request")
			return
		}
		req, der, err := protocol.DecodeRenewalRequest(data)
		if err != nil {
			fail(400, "invalid_request")
			return
		}
		csr, err := ParseCSR(der)
		if err != nil {
			fail(400, "invalid_request")
			return
		}
		response, err := store.RenewCertificate(r.Context(), old, r.TLS.VerifiedChains[0][1], req.RenewalID, csr, issuer, audit.Peer(r.RemoteAddr))
		if err != nil {
			fail(409, "renewal_rejected")
			return
		}
		_, _ = w.Write(response)
	})
}
