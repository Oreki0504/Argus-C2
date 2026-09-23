package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func main() {
	log.SetFlags(0)
	address := flag.String("server", "https://127.0.0.1:8443", "server HTTPS origin")
	cert := flag.String("cert", "", "probe certificate PEM file")
	key := flag.String("key", "", "probe private key PEM file")
	ca := flag.String("ca", "", "server CA bundle PEM file")
	identityFile := flag.String("identity", "", "local node identity JSON file")
	flag.Parse()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		log.Fatal("the probe must run as a non-root user")
	}
	if flag.NArg() != 0 || *cert == "" || *key == "" || *ca == "" || *identityFile == "" {
		log.Fatal("required: -cert, -key, -ca, -identity; no positional arguments")
	}
	u, err := agent.ServerURL(*address)
	if err != nil {
		log.Fatal(err)
	}
	node, err := identity.LoadNode(*identityFile)
	if err != nil {
		log.Fatal(err)
	}
	config, err := tlsconfig.Client(tlsconfig.Files{Certificate: *cert, PrivateKey: *key, CA: *ca}, node, u.Hostname())
	if err != nil {
		log.Fatal(err)
	}
	client, err := agent.NewClient(*address, config, node)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
		log.Fatal(err)
	}
}
