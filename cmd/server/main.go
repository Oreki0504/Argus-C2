package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func main() {
	log.SetFlags(0)
	addr := flag.String("listen", "127.0.0.1:8443", "literal loopback address")
	cert := flag.String("cert", "", "server certificate PEM file")
	key := flag.String("key", "", "server private key PEM file")
	ca := flag.String("ca", "", "client CA bundle PEM file")
	registrations := flag.String("registry", "", "locally provisioned probe registry JSON file")
	flag.Parse()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		log.Fatal("the server must run as a non-root user")
	}
	if flag.NArg() != 0 || *cert == "" || *key == "" || *ca == "" || *registrations == "" {
		log.Fatal("required: -cert, -key, -ca, -registry; no positional arguments")
	}
	if err := server.LoopbackAddress(*addr); err != nil {
		log.Fatal(err)
	}
	registry, err := identity.LoadRegistry(*registrations)
	if err != nil {
		log.Fatal(err)
	}
	config, err := tlsconfig.Server(tlsconfig.Files{Certificate: *cert, PrivateKey: *key, CA: *ca}, registry)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("Starting Phase 2 identity-check endpoint on %s", *addr)
	if err := server.Run(ctx, *addr, config, registry); err != nil {
		log.Fatal(err)
	}
}
