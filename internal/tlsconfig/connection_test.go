package tlsconfig_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func TestPooledTLSValidity(t *testing.T) {
	for _, boundary := range []string{"server leaf", "peer root", "client leaf", "clock rollback"} {
		t.Run(boundary, func(t *testing.T) {
			ca, err := devpki.NewAuthority()
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().Truncate(time.Second)
			st := devpki.ServerTemplate()
			st.NotAfter = now.Add(48 * time.Hour)
			ct, err := devpki.ClientTemplate(identity.New())
			if err != nil {
				t.Fatal(err)
			}
			ct.NotAfter = st.NotAfter
			cutoff := ca.Certificate.NotAfter
			if boundary == "server leaf" {
				st.NotAfter = now.Add(time.Hour)
				cutoff = st.NotAfter
			}
			if boundary == "client leaf" {
				ct.NotAfter = now.Add(time.Hour)
				cutoff = ct.NotAfter
			}
			if boundary == "clock rollback" {
				cutoff = st.NotBefore.Add(-time.Second)
			}
			serverCert, err := ca.Issue(st)
			if err != nil {
				t.Fatal(err)
			}
			clientCert, err := ca.Issue(ct)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca.Certificate)
			var received atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					return
				}
				received.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.TLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, SessionTicketsDisabled: true}
			s.StartTLS()
			defer s.Close()
			var clock atomic.Int64
			clock.Store(now.UnixNano())
			cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert.TLS}, ServerName: "localhost", Time: func() time.Time { return time.Unix(0, clock.Load()) }}
			tr := &http.Transport{DialTLSContext: tlsconfig.ClientDialContext(cfg), TLSClientConfig: cfg}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			post := func() (bool, error) {
				reused := false
				ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }})
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewBufferString("sensitive request"))
				if err != nil {
					return false, err
				}
				resp, err := client.Do(req)
				if err != nil {
					return reused, err
				}
				defer resp.Body.Close()
				_, err = io.Copy(io.Discard, resp.Body)
				return reused, err
			}
			if _, err := post(); err != nil {
				t.Fatal(err)
			}
			if reused, err := post(); err != nil || !reused {
				t.Fatal("connection was not reused", reused, err)
			}
			clock.Store(cutoff.UnixNano())
			if _, err := post(); err == nil {
				t.Fatal("accepted request outside credential validity")
			}
			if received.Load() != 2 {
				t.Fatal("request escaped before expiry rejection", received.Load())
			}
		})
	}
}
