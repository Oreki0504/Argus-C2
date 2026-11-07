package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/api"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}
func TestConsoleSeparateTLSListenersAndShutdown(t *testing.T) {
	root := t.TempDir()
	fleetDir, browserDir := filepath.Join(root, "fleet"), filepath.Join(root, "browser")
	for _, dir := range []string{fleetDir, browserDir} {
		if err := enrollment.Initialize(dir, []string{"localhost", "127.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := database.Open(filepath.Join(root, "state"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fleetCA := filepath.Join(fleetDir, "ca.pem")
	if srv, err := (consoleFlags{}).server(store, filepath.Join(root, "state"), fleetCA); err != nil || srv != nil {
		t.Fatal("Console is not disabled by default", err)
	}
	if _, err = (consoleFlags{listen: "127.0.0.1:9443"}).server(store, filepath.Join(root, "state"), fleetCA); err == nil {
		t.Fatal("partial flags accepted")
	}
	if _, err = transport.ConsoleServer(filepath.Join(fleetDir, "server.pem"), filepath.Join(fleetDir, "server-key.pem"), "https://localhost:9443", fleetCA); err == nil {
		t.Fatal("Fleet certificate accepted for browser")
	}
	if _, err = transport.ConsoleServer(filepath.Join(browserDir, "server.pem"), filepath.Join(browserDir, "server-key.pem"), "https://wrong.example", fleetCA); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	address := freeAddress(t)
	flags := consoleFlags{listen: address, origin: "https://" + address, cert: filepath.Join(browserDir, "server.pem"), key: filepath.Join(browserDir, "server-key.pem")}
	browser, err := flags.server(store, filepath.Join(root, "state"), fleetCA)
	if err != nil {
		t.Fatal(err)
	}
	fleetTLS, err := transport.Server(filepath.Join(fleetDir, "server.pem"), filepath.Join(fleetDir, "server-key.pem"), fleetCA)
	if err != nil {
		t.Fatal(err)
	}
	fleet := &http.Server{Addr: freeAddress(t), TLSConfig: fleetTLS, Handler: (&api.Server{Store: store}).Handler()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveListeners(ctx, fleet, browser) }()
	client, err := transport.Client(filepath.Join(browserDir, "ca.pem"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	client.Timeout = time.Second
	var resp *http.Response
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		resp, err = client.Get(flags.origin + "/v1/console/auth/status")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if len(resp.TLS.PeerCertificates) != 1 {
		t.Fatal("unexpected Console TLS chain")
	}
	fleetClient, err := transport.Client(fleetCA, "", "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err = fleetClient.Get("https://" + fleet.Addr + "/v1/console/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("Console mounted on Fleet", resp.StatusCode)
	}
	resp, err = client.Get(flags.origin + "/v1/enroll")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("enrollment on Console", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listeners did not shut down")
	}
	for _, addr := range []string{fleet.Addr, browser.Addr} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal("listener remained open", err)
		}
		ln.Close()
	}
}
func TestConsoleListenerBindFailureClosesFleet(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	fleetAddr := freeAddress(t)
	if err = serveListeners(context.Background(), &http.Server{Addr: fleetAddr}, &http.Server{Addr: busy.Addr().String()}); err == nil {
		t.Fatal("bind failure ignored")
	}
	ln, err := net.Listen("tcp", fleetAddr)
	if err != nil {
		t.Fatal("Fleet left bound", err)
	}
	ln.Close()
}
