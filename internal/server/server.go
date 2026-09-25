// Package server exposes loopback-only development APIs with live authorization.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const IdentityPath = "/api/v1/agent/identity"
const HeartbeatPath = "/api/v1/agent/heartbeat"

type TelemetryStore interface {
	SaveHeartbeat(context.Context, *x509.Certificate, protocol.Heartbeat) error
}

// A persistent sink enables telemetry; a Dispatcher also enables typed tasks.
func Handler(registry identity.Authorizer, sinks ...TelemetryStore) http.Handler {
	var sink TelemetryStore
	if len(sinks) == 1 {
		sink = sinks[0]
	}
	slots := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(status int, code protocol.ErrorCode) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Code: code})
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			fail(http.StatusTooManyRequests, protocol.ErrorCode("rate_limited"))
			return
		}
		if registry == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
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
		if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(http.StatusBadRequest, protocol.InvalidRequest)
			return
		}
		if dispatcher, ok := sink.(Dispatcher); ok && (r.URL.Path == PollPath || r.URL.Path == ResultsPath) {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				fail(405, protocol.MethodNotAllowed)
				return
			}
			limit := 256
			if r.URL.Path == ResultsPath {
				limit = protocol.MaxDispatchResultBytes
			}
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" || r.ContentLength <= 0 || r.ContentLength > int64(limit) || len(r.TransferEncoding) != 0 {
				fail(400, protocol.InvalidRequest)
				return
			}
			data, err := strictjson.Read(r.Body, limit)
			if err != nil {
				fail(400, protocol.InvalidRequest)
				return
			}
			if r.URL.Path == PollPath {
				request, err := protocol.DecodePoll(data)
				if err != nil {
					fail(400, protocol.InvalidRequest)
					return
				}
				envelope, err := dispatcher.PollTask(r.Context(), r.TLS.PeerCertificates[0], request.PolicyDigest, audit.Peer(r.RemoteAddr))
				if err != nil {
					fail(503, protocol.ErrorCode("dispatch_unavailable"))
					return
				}
				if len(envelope) == 0 {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				_, _ = w.Write(envelope)
				return
			}
			ack, err := dispatcher.SubmitResult(r.Context(), r.TLS.PeerCertificates[0], data, audit.Peer(r.RemoteAddr))
			if err != nil {
				fail(409, protocol.ErrorCode("result_rejected"))
				return
			}
			_ = json.NewEncoder(w).Encode(ack)
			return
		}
		if r.URL.Path == HeartbeatPath && sink != nil {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				fail(http.StatusMethodNotAllowed, protocol.MethodNotAllowed)
				return
			}
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" || r.ContentLength <= 0 || r.ContentLength > protocol.MaxHeartbeatBytes || len(r.TransferEncoding) != 0 {
				fail(http.StatusBadRequest, protocol.InvalidRequest)
				return
			}
			data, err := strictjson.Read(r.Body, protocol.MaxHeartbeatBytes)
			if err != nil {
				fail(http.StatusBadRequest, protocol.InvalidRequest)
				return
			}
			h, err := protocol.DecodeHeartbeat(data)
			if err != nil || h.AgentID != node.AgentID || h.EnrollmentEpoch != node.EnrollmentEpoch || h.SentAt < now.Unix()-300 || h.SentAt > now.Unix()+30 {
				fail(http.StatusBadRequest, protocol.InvalidRequest)
				return
			}
			if err := sink.SaveHeartbeat(r.Context(), r.TLS.PeerCertificates[0], h); err != nil {
				if errors.Is(err, state.ErrRateLimited) {
					fail(http.StatusTooManyRequests, protocol.ErrorCode("rate_limited"))
				} else {
					fail(http.StatusServiceUnavailable, protocol.ErrorCode("unavailable"))
				}
				return
			}
			_ = json.NewEncoder(w).Encode(protocol.ConnectionInfo{Version: protocol.Version, AgentID: node.AgentID, EnrollmentEpoch: node.EnrollmentEpoch})
			return
		}
		if r.URL.Path != IdentityPath {
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
		return errors.New("development APIs require a literal loopback listening address")
	}
	return nil
}

func Run(ctx context.Context, addr string, config *tls.Config, registry identity.Authorizer, sinks ...TelemetryStore) error {
	if err := LoopbackAddress(addr); err != nil {
		return err
	}
	if config == nil || config.MinVersion < tls.VersionTLS13 || config.ClientAuth != tls.RequireAndVerifyClientCert || config.VerifyConnection == nil || config.ClientCAs == nil || registry == nil {
		return errors.New("verified mTLS configuration and registry are required")
	}
	return runHTTP(ctx, addr, config, Handler(registry, sinks...))
}

func RunEnrollment(ctx context.Context, addr string, config *tls.Config, handler http.Handler) error {
	if err := LoopbackAddress(addr); err != nil {
		return err
	}
	if config == nil || config.MinVersion < tls.VersionTLS13 || config.ClientAuth != tls.NoClientCert || handler == nil {
		return errors.New("separate verified TLS enrollment listener is required")
	}
	return runHTTP(ctx, addr, config, handler)
}

func RunAdministration(ctx context.Context, addr string, config *tls.Config, handler http.Handler) error {
	if err := LoopbackAddress(addr); err != nil {
		return err
	}
	if config == nil || config.MinVersion < tls.VersionTLS13 || config.ClientAuth != tls.NoClientCert || handler == nil {
		return errors.New("separate TLS administrator listener is required")
	}
	return runHTTP(ctx, addr, config, handler)
}

func runHTTP(ctx context.Context, addr string, config *tls.Config, handler http.Handler) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := &http.Server{Handler: handler, TLSConfig: config.Clone(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	stopped := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
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
	close(stopped)
	// ServeTLS returns as soon as listeners close. Wait for active handlers to
	// drain before callers close the SQLite store used by those handlers.
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
