package tlsconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

type validityWindow struct{ start, end time.Time }
type validityConn struct {
	net.Conn
	now    func() time.Time
	window atomic.Pointer[validityWindow]
}

func (c *validityConn) check() error {
	w := c.window.Load()
	if w == nil {
		return nil
	} // Initial handshake performs normal X.509 verification.
	now := c.now()
	if now.Before(w.start) || !now.Before(w.end) {
		c.Conn.Close()
		return errors.New("TLS credential chain is outside its validity window")
	}
	return nil
}
func (c *validityConn) Write(b []byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}
func (c *validityConn) Read(b []byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(b)
	if invalid := c.check(); invalid != nil {
		return 0, invalid
	}
	return n, err
}

// ClientDialContext retains normal TLS verification and HTTP connection reuse,
// but checks the verified peer chain and presented local certificates on each
// underlying TLS record read/write. Expiry cannot authorize a later request on
// an already established connection. No trust or time override is exposed by CLI.
func ClientDialContext(config *tls.Config) func(context.Context, string, string) (net.Conn, error) {
	cfg := config.Clone()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if cfg.InsecureSkipVerify || cfg.RootCAs == nil || cfg.ServerName == "" || cfg.MinVersion < tls.VersionTLS13 {
			return nil, errors.New("verified TLS 1.3 configuration required")
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		now := cfg.Time
		if now == nil {
			now = time.Now
		}
		guard := &validityConn{Conn: raw, now: now}
		conn := tls.Client(guard, cfg)
		handshake, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := conn.HandshakeContext(handshake); err != nil {
			raw.Close()
			return nil, err
		}
		state := conn.ConnectionState()
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			raw.Close()
			return nil, errors.New("verified peer chain required")
		}
		certs := append([]*x509.Certificate{}, state.VerifiedChains[0]...)
		for _, pair := range cfg.Certificates {
			for _, der := range pair.Certificate {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					raw.Close()
					return nil, err
				}
				certs = append(certs, c)
			}
		}
		window := &validityWindow{start: certs[0].NotBefore, end: certs[0].NotAfter}
		for _, c := range certs[1:] {
			if c.NotBefore.After(window.start) {
				window.start = c.NotBefore
			}
			if c.NotAfter.Before(window.end) {
				window.end = c.NotAfter
			}
		}
		guard.window.Store(window)
		if err := guard.check(); err != nil {
			return nil, err
		}
		return conn, nil
	}
}
