package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
)

func TestShutdownDrainsHandlersBeforeReturning(t *testing.T) {
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runHTTP(ctx, address, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{b.Server.TLS}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(204) }))
	}()
	roots := x509.NewCertPool()
	roots.AddCert(b.CA.Certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	result := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			resp, err := client.Get("https://" + address)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				result <- nil
				return
			}
			if time.Now().After(deadline) {
				result <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	select {
	case <-entered:
	case err := <-result:
		close(release)
		t.Fatal("request did not reach server", err)
	case <-time.After(4 * time.Second):
		close(release)
		t.Fatal("server did not start")
	}
	cancel()
	select {
	case err := <-done:
		close(release)
		t.Fatal("server returned before draining active handler", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	if err := <-result; err != nil {
		t.Fatal("active response lost during shutdown", err)
	}
}
