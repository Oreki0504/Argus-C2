package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("listen", "127.0.0.1:8443", "literal loopback address")
	cert := flag.String("cert", "", "server certificate PEM file")
	key := flag.String("key", "", "server private key PEM file")
	ca := flag.String("ca", "", "client CA bundle PEM file")
	registrations := flag.String("registry", "", "locally provisioned probe registry JSON file")
	stateDir := flag.String("state", "", "private SQLite state directory (instead of -registry)")
	enrollAddr := flag.String("enroll-listen", "", "enable a separate loopback enrollment listener")
	issuerCert := flag.String("issuer-cert", "", "client-auth-only intermediate CA certificate")
	issuerKey := flag.String("issuer-key", "", "intermediate CA private key")
	flag.Parse()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return errors.New("the server must run as a non-root user")
	}
	if flag.NArg() != 0 || *cert == "" || *key == "" || *ca == "" || (*registrations == "") == (*stateDir == "") {
		return errors.New("required: -cert, -key, -ca and exactly one of -registry or -state; no positional arguments")
	}
	if err := server.LoopbackAddress(*addr); err != nil {
		return err
	}
	var registry identity.Authorizer
	var sinks []server.TelemetryStore
	var store *state.Store
	var err error
	if *stateDir != "" {
		store, err = state.Open(*stateDir)
		if err != nil {
			return err
		}
		defer store.Close()
		registry = store
		sinks = []server.TelemetryStore{store}
	} else {
		registry, err = identity.LoadRegistry(*registrations)
		if err != nil {
			return err
		}
	}
	files := tlsconfig.Files{Certificate: *cert, PrivateKey: *key, CA: *ca}
	config, err := tlsconfig.Server(files, registry)
	if err != nil {
		return err
	}
	var issuer *enrollment.Issuer
	var enrollmentTLS *tls.Config
	if *enrollAddr != "" {
		if store == nil || *issuerCert == "" || *issuerKey == "" || *issuerKey == *key {
			return errors.New("enrollment requires -state and separate -issuer-cert/-issuer-key")
		}
		if err := server.LoopbackAddress(*enrollAddr); err != nil {
			return err
		}
		issuer, err = enrollment.LoadIssuer(*issuerCert, *issuerKey, *ca)
		if err != nil {
			return err
		}
		if err := issuer.CheckTransport(config.Certificates[0].Leaf); err != nil {
			return err
		}
		enrollmentTLS, err = tlsconfig.EnrollmentServer(files)
		if err != nil {
			return err
		}
	} else if *issuerCert != "" || *issuerKey != "" {
		return errors.New("issuer credentials require explicit -enroll-listen")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	count := 1
	log.Printf("Starting mTLS probe endpoint on %s", *addr)
	go func() { results <- server.Run(ctx, *addr, config, registry, sinks...) }()
	if issuer != nil {
		count++
		log.Printf("Starting development enrollment endpoint on %s", *enrollAddr)
		go func() {
			results <- server.RunEnrollment(ctx, *enrollAddr, enrollmentTLS, enrollment.Handler(store, issuer))
		}()
	}
	var first error
	for i := 0; i < count; i++ {
		err := <-results
		if err != nil && first == nil {
			first = fmt.Errorf("server listener: %w", err)
		}
		cancel()
	}
	return first
}
