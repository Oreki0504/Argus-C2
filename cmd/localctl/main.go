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

	"github.com/Oreki0504/Argus-C2/internal/protocol"
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
	action := flag.String("action", "nodes", "token, nodes, disable, submit, tasks, or audit")
	ttl := flag.Duration("ttl", 10*time.Minute, "enrollment token lifetime, at most 15 minutes")
	id := flag.String("agent-id", "", "node to disable or submit to")
	kind := flag.String("type", "", "system.info, system.metrics, ssh.audit, or service.status (submit only)")
	profileID := flag.String("profile-id", "", "local SSH profile ID for ssh.audit")
	serviceID := flag.String("service-id", "", "local service ID for service.status")
	actor := flag.String("actor-id", "local-operator", "local audit label; not an authenticated administrator identity")
	taskTTL := flag.Duration("task-ttl", 2*time.Minute, "task lifetime, 1 second through 5 minutes")
	after := flag.Int64("after", 0, "task or audit sequence cursor")
	limit := flag.Int("limit", 100, "page size, 1 through 200")
	flag.Parse()
	if flag.NArg() != 0 || *dir == "" {
		return errors.New("required: -state; no positional arguments")
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return errors.New("run localctl as the non-root server user")
	}
	if *action != "token" && *action != "nodes" && *action != "disable" && *action != "submit" && *action != "tasks" && *action != "audit" {
		return errors.New("unknown local action")
	}
	if (*action == "disable" || *action == "submit") != (*id != "") {
		return errors.New("-agent-id is required only for disable or submit")
	}
	if (*action == "submit") != (*kind != "") {
		return errors.New("-type is required only for submit")
	}
	params := json.RawMessage(`{}`)
	if *action == "submit" && *kind == string(protocol.SSHAudit) {
		if !protocol.ResourceID(*profileID) || *serviceID != "" {
			return errors.New("ssh.audit requires only -profile-id")
		}
		params, _ = json.Marshal(map[string]string{"profile_id": *profileID})
	} else if *action == "submit" && *kind == string(protocol.ServiceStatus) {
		if !protocol.ResourceID(*serviceID) || *profileID != "" {
			return errors.New("service.status requires only -service-id")
		}
		params, _ = json.Marshal(map[string]string{"service_id": *serviceID})
	} else if *profileID != "" || *serviceID != "" {
		return errors.New("resource flags apply only to their matching task type")
	}
	s, err := state.Open(*dir)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	case "submit":
		task, err := s.Enqueue(ctx, *id, protocol.TaskType(*kind), *actor, *taskTTL, params)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(task)
	case "tasks":
		tasks, err := s.Tasks(ctx, *after, *limit)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(tasks)
	case "audit":
		page, err := s.Audit(ctx, *after, *limit)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(page)
	}
	return nil
}
