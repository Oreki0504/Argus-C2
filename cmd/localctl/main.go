// localctl is a development-only operator tool requiring direct state access.
// It is not the authenticated administration CLI planned for Phase 6.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/state"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	dir := flag.String("state", "", "private server state directory")
	action := flag.String("action", "nodes", "token, nodes, or disable")
	ttl := flag.Duration("ttl", 10*time.Minute, "enrollment token lifetime, at most 15 minutes")
	id := flag.String("agent-id", "", "node to disable")
	flag.Parse()
	if flag.NArg() != 0 || *dir == "" {
		return errors.New("required: -state; no positional arguments")
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return errors.New("run localctl as the non-root server user")
	}
	if *action != "token" && *action != "nodes" && *action != "disable" {
		return errors.New("unknown local action")
	}
	if (*action == "disable") != (*id != "") {
		return errors.New("-agent-id is required only for disable")
	}
	s, err := state.Open(*dir)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch *action {
	case "token":
		token, err := s.IssueToken(ctx, *ttl)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, token)
		return err
	case "nodes":
		nodes, err := s.Snapshots(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(nodes)
	case "disable":
		return s.Disable(ctx, *id)
	}
	return nil
}
