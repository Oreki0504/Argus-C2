package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/console"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

type consoleFlags struct{ listen, origin, cert, key, installerDir, fleetOrigin string }

func (c consoleFlags) server(store *database.Store, stateDir, fleetCA string) (*http.Server, error) {
	if c.listen == "" && c.origin == "" && c.cert == "" && c.key == "" && c.installerDir == "" && c.fleetOrigin == "" {
		return nil, nil
	}
	if c.listen == "" || c.origin == "" || c.cert == "" || c.key == "" {
		return nil, errors.New("Console requires -console-listen, -console-origin, -console-cert and -console-key together")
	}
	if _, _, err := net.SplitHostPort(c.listen); err != nil {
		return nil, err
	}
	tlsConfig, err := transport.ConsoleServer(c.cert, c.key, c.origin, fleetCA)
	if err != nil {
		return nil, err
	}
	app, err := console.New(store, console.Config{Origin: c.origin, StateDir: stateDir, InstallerDir: c.installerDir, FleetOrigin: c.fleetOrigin, FleetCA: fleetCA})
	if err != nil {
		return nil, err
	}
	return &http.Server{Addr: c.listen, Handler: app.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}, nil
}
func consoleMigrateCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("console-migrate", flag.ContinueOnError)
	file := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	backup := f.String("backup", "", "new backup file in a private directory")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *backup == "" {
		return errors.New("console-migrate requires -config and -backup; stop the server first")
	}
	c, err := config.LoadServer(*file)
	if err != nil {
		return err
	}
	if err = database.MigrateConsole(context.Background(), c.StateDir, *backup); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "Server schema migrated 102 -> 103; verified pre-upgrade backup:", *backup)
	return err
}
func consoleBootstrapCommand(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "issue" && args[0] != "recover" {
		return errors.New("usage: server console-bootstrap issue|recover -config FILE -out NEW_PRIVATE_FILE [-confirm-recovery]")
	}
	recovery := args[0] == "recover"
	f := flag.NewFlagSet("console-bootstrap "+args[0], flag.ContinueOnError)
	file := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	dest := f.String("out", "", "new private file for the one-time secret")
	confirm := f.Bool("confirm-recovery", false, "revoke Console sessions now and replace former Admin access after successful binding")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || *dest == "" || recovery && !*confirm || !recovery && *confirm {
		return errors.New("new -out required; recover additionally requires -confirm-recovery")
	}
	c, err := config.LoadServer(*file)
	if err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(*dest))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return errors.New("secret output directory must be private and non-symlink")
	}
	store, err := database.Open(c.StateDir, false)
	if err != nil {
		return err
	}
	defer store.Close()
	fh, err := os.OpenFile(*dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer fh.Close()
	secret, err := store.IssueConsoleBootstrap(context.Background(), recovery)
	if err != nil {
		_ = os.Remove(*dest)
		return err
	}
	if _, err = io.WriteString(fh, secret+"\n"); err != nil {
		return err
	}
	if err = fh.Sync(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "One-time Console setup secret saved to", *dest, "(15-minute lifetime). Open /setup on the HTTPS Console.")
	return err
}

// Bind all listeners before serving any requests. Failure on either port stops
// both servers, and signal shutdown drains both under the same bounded deadline.
func serveListeners(ctx context.Context, servers ...*http.Server) error {
	listeners := make([]net.Listener, 0, len(servers))
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			for _, open := range listeners {
				open.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}
	done := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { done <- srv.ServeTLS(listeners[i], "", "") }()
	}
	var first error
	select {
	case first = <-done:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		go func() {
			err := srv.Shutdown(shutdown)
			if err != nil {
				srv.Close()
			}
			errs <- err
		}()
	}
	for range servers {
		if err := <-errs; err != nil && first == nil {
			first = err
		}
	}
	if errors.Is(first, http.ErrServerClosed) {
		return nil
	}
	return first
}
