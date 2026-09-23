// Package server exposes only a loopback identity-check endpoint in Phase 2.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const IdentityPath = "/api/v1/agent/identity"

func Handler(registry *identity.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(status int, code protocol.ErrorCode) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Code: code})
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			fail(http.StatusUnauthorized, protocol.Unauthorized)
			return
		}
		// Normal chain verification happened at the handshake. Recheck the
		// selected chain's validity dates on long-lived HTTP connections.
		now := time.Now()
		for _, cert := range r.TLS.VerifiedChains[0] {
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				fail(http.StatusUnauthorized, protocol.Unauthorized)
				return
			}
		}
		// Recheck even on an established keep-alive connection after disablement.
		node, err := registry.Authorize(r.TLS.PeerCertificates[0])
		if err != nil {
			fail(http.StatusUnauthorized, protocol.Unauthorized)
			return
		}
		if r.URL.Path != IdentityPath || r.URL.RawPath != "" {
			fail(http.StatusNotFound, protocol.NotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			fail(http.StatusMethodNotAllowed, protocol.MethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			fail(http.StatusBadRequest, protocol.InvalidRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.ConnectionInfo{Version: protocol.Version, AgentID: node.AgentID, EnrollmentEpoch: node.EnrollmentEpoch})
	})
}

func LoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("Phase 2 requires a literal loopback listening address")
	}
	return nil
}

func Run(ctx context.Context, addr string, config *tls.Config, registry *identity.Registry) error {
	if err := LoopbackAddress(addr); err != nil {
		return err
	}
	if config == nil || config.MinVersion < tls.VersionTLS13 || config.ClientAuth != tls.RequireAndVerifyClientCert || config.VerifyConnection == nil || config.ClientCAs == nil || registry == nil {
		return errors.New("verified mTLS configuration and registry are required")
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := &http.Server{Handler: Handler(registry), TLSConfig: config.Clone(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := s.Shutdown(shutdown); err != nil {
				_ = s.Close()
			}
		case <-stopped:
		}
	}()
	err = s.ServeTLS(l, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
