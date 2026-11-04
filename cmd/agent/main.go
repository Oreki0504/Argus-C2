package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"encoding/json"
	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if e := run(); e != nil {
		slog.Error("agent stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: agent enroll|run|renew|storage|results|result-export|result-retry|result-discard [flags]")
	}
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	path := f.String("config", "/etc/argus-c2/agent.json", "local agent configuration")
	tokenFile := f.String("token-file", "", "private single-use enrollment token file")
	check := f.Bool("check", false, "validate configuration and exit")
	taskID := f.String("task", "", "local task ID for result maintenance")
	after := f.String("after", "", "local result pagination cursor")
	out := f.String("out", "", "new private result export file")
	confirm := f.String("confirm-task", "", "explicit task ID confirmation for noninteractive discard")
	once := f.Bool("once", false, "perform one collection cycle")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	c, p, e := config.LoadAgent(*path)
	if e != nil {
		return e
	}
	if *check {
		fmt.Println("agent configuration valid")
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("the node agent requires Linux")
	}
	if os.Geteuid() == 0 {
		return errors.New("run the agent as a dedicated non-root user")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch os.Args[1] {
	case "storage", "results", "result-export", "result-retry", "result-discard":
		state, e := agent.OpenLocal(c.StateDir)
		if e != nil {
			return e
		}
		defer state.Close()
		if os.Args[1] == "storage" {
			storage, e := localdb.InspectStorage(c.StateDir, "probe.db")
			if e != nil {
				return e
			}
			capacity, e := state.Capacity(ctx)
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(struct {
				Storage localdb.Storage      `json:"storage"`
				Results agent.ResultCapacity `json:"results"`
			}{storage, capacity})
		}
		return maintain(ctx, state, os.Args[1], *taskID, *after, *out, *confirm, os.Stdin, os.Stdout, os.Stderr)
	}
	if os.Args[1] == "enroll" {
		b, e := localfile.Read(*tokenFile, 1024, true)
		if e != nil {
			return e
		}
		hostname, e := os.Hostname()
		if e != nil {
			return e
		}
		if e = agent.Enroll(ctx, c.Server, c.CA, c.StateDir, strings.TrimSpace(string(b)), hostname); e != nil {
			return e
		}
		fmt.Println("node enrolled")
		return nil
	}
	if os.Args[1] != "run" && os.Args[1] != "renew" {
		return errors.New("unknown agent command")
	}
	r, e := agent.Open(c.Server, c.CA, c.StateDir, p)
	if e != nil {
		return e
	}
	defer r.Close()
	if os.Args[1] == "renew" {
		return r.Renew(ctx)
	}
	if *once {
		return r.Step(ctx)
	}
	return r.Run(ctx)
}
