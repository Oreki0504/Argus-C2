package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/api"
	"github.com/Oreki0504/Argus-C2/internal/auth"
	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if e := run(); e != nil {
		slog.Error("server stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: server init|run|backup|storage|prune|certificates|console-migrate|console-bootstrap|console-token [flags]")
	}
	if os.Args[1] == "console-migrate" {
		return consoleMigrateCommand(os.Args[2:], os.Stdout)
	}
	if os.Args[1] == "console-bootstrap" {
		return consoleBootstrapCommand(os.Args[2:], os.Stdout)
	}
	if os.Args[1] == "console-token" {
		return consoleSecretCommand(os.Args[2:], os.Stdout, true)
	}
	if os.Args[1] == "prune" {
		return pruneCommand(os.Args[2:], os.Stdout)
	}
	if os.Args[1] == "certificates" {
		return certificatesCommand(os.Args[2:], os.Stdout)
	}
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	dir := f.String("dir", "", "new private server directory")
	hosts := f.String("hosts", "localhost,127.0.0.1", "comma-separated server DNS names/IPs")
	listen := f.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	file := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	check := f.Bool("check", false, "validate configuration and exit")
	out := f.String("out", "", "new backup file in a private directory")
	var browser consoleFlags
	f.StringVar(&browser.listen, "console-listen", "", "optional Console HTTPS listen address, e.g. 0.0.0.0:9443")
	f.StringVar(&browser.origin, "console-origin", "", "exact browser HTTPS origin")
	f.StringVar(&browser.cert, "console-cert", "", "browser TLS certificate, independent of Fleet CA")
	f.StringVar(&browser.key, "console-key", "", "private browser TLS key")
	f.StringVar(&browser.installerDir, "console-installer-dir", "", "optional directory of published agent-linux-amd64 and/or agent-linux-arm64 binaries")
	f.StringVar(&browser.fleetOrigin, "console-fleet-origin", "", "reachable Fleet HTTPS origin used by installed Agents; requires -console-installer-dir")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if os.Args[1] == "init" {
		if *dir == "" {
			return errors.New("-dir is required")
		}
		abs, e := filepath.Abs(*dir)
		if e != nil {
			return e
		}
		if _, e = os.Stat(abs); !os.IsNotExist(e) {
			return errors.New("initialization requires a new directory")
		}
		if e = enrollment.Initialize(abs, strings.Split(*hosts, ",")); e != nil {
			return e
		}
		stateDir := filepath.Join(abs, "state")
		store, e := database.Open(stateDir, true)
		if e != nil {
			return e
		}
		if e = store.Close(); e != nil {
			return e
		}
		user, token, e := auth.NewUser("admin", "Admin")
		if e != nil {
			return e
		}
		admins := filepath.Join(abs, "admins.json")
		if e = writeJSON(admins, auth.Config{Users: []auth.User{user}}); e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(abs, "admin.token"), []byte(token+"\n"), 0600); e != nil {
			return e
		}
		c := config.Server{Listen: *listen, StateDir: stateDir, Certificate: filepath.Join(abs, "server.pem"), PrivateKey: filepath.Join(abs, "server-key.pem"), CA: filepath.Join(abs, "ca.pem"), IssuerKey: filepath.Join(abs, "ca-key.pem"), Admins: admins}
		if e = writeJSON(filepath.Join(abs, "server.json"), c); e != nil {
			return e
		}
		fmt.Println("Initialized", abs, "; administrator token saved to admin.token")
		return nil
	}
	c, e := config.LoadServer(*file)
	if e != nil {
		return e
	}
	if os.Args[1] == "run" {
		lock, err := localdb.LockServer(c.StateDir)
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	store, e := database.Open(c.StateDir, false)
	if e != nil {
		return e
	}
	defer store.Close()
	if os.Args[1] == "storage" {
		report, e := localdb.InspectStorage(c.StateDir, "argus.db")
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if os.Args[1] == "backup" {
		if *out == "" {
			return errors.New("-out is required")
		}
		parent, e := os.Stat(filepath.Dir(*out))
		if e != nil {
			return e
		}
		if !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
			return errors.New("backup directory must have mode 0700")
		}
		if e = store.Backup(context.Background(), *out); e != nil {
			return e
		}
		return os.Chmod(*out, 0600)
	}
	if os.Args[1] != "run" {
		return errors.New("unknown server command")
	}
	admins, e := auth.Load(c.Admins)
	if e != nil {
		return e
	}
	issuer, e := enrollment.Load(c.CA, c.IssuerKey)
	if e != nil {
		return e
	}
	tlsConfig, e := transport.Server(c.Certificate, c.PrivateKey, c.CA)
	if e != nil {
		return e
	}
	consoleServer, e := browser.server(store, c.StateDir, c.CA)
	if e != nil {
		return e
	}
	if *check {
		fmt.Println("server configuration valid")
		return nil
	}
	handler := (&api.Server{Store: store, Enrollment: enrollment.Service{Store: store, Issuer: issuer}, Admins: admins}).Handler()
	server := &http.Server{Addr: c.Listen, Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	servers := []*http.Server{server}
	if consoleServer != nil {
		servers = append(servers, consoleServer)
		slog.Info("Console configured", "address", consoleServer.Addr, "origin", browser.origin)
	}
	slog.Info("Fleet configured", "address", c.Listen)
	return serveListeners(ctx, servers...)
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
