package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/collector"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/signing"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func main() {
	log.SetFlags(0)
	address := flag.String("server", "https://127.0.0.1:8443", "server HTTPS origin")
	cert := flag.String("cert", "", "probe certificate PEM file")
	key := flag.String("key", "", "probe private key PEM file")
	ca := flag.String("ca", "", "server CA bundle PEM file")
	identityFile := flag.String("identity", "", "local node identity JSON file")
	telemetry := flag.String("config", "", "local telemetry JSON configuration; omission checks identity once")
	once := flag.Bool("once", false, "run one telemetry or task cycle, then exit")
	policyFile := flag.String("policy", "", "local task and telemetry policy (instead of -config)")
	stateDir := flag.String("task-state", "", "existing probe replay state initialized with probectl")
	taskKey := flag.String("task-public-key", "", "locally pinned task verification key")
	flag.Parse()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		log.Fatal("the probe must run as a non-root user")
	}
	if flag.NArg() != 0 || *cert == "" || *key == "" || *ca == "" || *identityFile == "" {
		log.Fatal("required: -cert, -key, -ca, -identity; no positional arguments")
	}
	if *once && *telemetry == "" && *policyFile == "" {
		log.Fatal("-once requires -config or -policy")
	}
	if *policyFile != "" && (*telemetry != "" || *stateDir == "" || *taskKey == "") {
		log.Fatal("-policy requires -task-state and -task-public-key and cannot be combined with -config")
	}
	if *policyFile == "" && (*stateDir != "" || *taskKey != "") {
		log.Fatal("task state and verification key require -policy")
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
	if *policyFile != "" {
		if err := runTasks(client, node, *policyFile, *stateDir, *taskKey, *once); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatal(err)
		}
		return
	}
	if *telemetry != "" {
		cfg, err := collector.LoadConfig(*telemetry)
		if err != nil {
			log.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = client.Run(ctx, cfg, *once, func(err error) {
			if err != nil {
				log.Println("Heartbeat failed; next attempt uses local backoff")
			} else {
				log.Println("Heartbeat accepted")
			}
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Fatal(err)
		}
		return
	}
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

func runTasks(client *agent.Client, node identity.Node, path, dir, keyFile string, once bool) error {
	if _, err := policy.Load(path); err != nil {
		return err
	}
	key, err := signing.LoadPublic(keyFile)
	if err != nil {
		return err
	}
	s, err := probe.Open(dir, node, key)
	if err != nil {
		log.Printf("Task execution blocked: %v; continuing telemetry only", err)
	} else {
		defer s.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return client.RunTasks(ctx, path, s, once, func(stage string, err error) {
		if err != nil {
			log.Printf("%s failed: %v", stage, err)
		} else {
			log.Printf("%s completed", stage)
		}
	})
}
