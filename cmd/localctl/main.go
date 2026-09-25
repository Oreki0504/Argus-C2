// localctl is a development-only operator tool requiring direct state access.
// cmd/cli provides authenticated network administration; localctl retains direct local authority.
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

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/secretinput"
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
	action := flag.String("action", "nodes", "token, nodes, disable, submit, tasks, audit, users, user-add, user-password, user-role, user-disable, user-revoke, or sessions-revoke-all")
	username := flag.String("username", "", "immutable administrator user name for local account actions")
	role := flag.String("role", "", "Admin or ReadOnly; user-add and user-role only")
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
	userAction := *action == "user-add" || *action == "user-password" || *action == "user-role" || *action == "user-disable" || *action == "user-revoke"
	if *action != "token" && *action != "nodes" && *action != "disable" && *action != "submit" && *action != "tasks" && *action != "audit" && *action != "users" && *action != "sessions-revoke-all" && !userAction {
		return errors.New("unknown local action")
	}
	if userAction != (*username != "") || (userAction && !adminauth.Username(*username)) {
		return errors.New("-username is required only for local user actions")
	}
	needsRole := *action == "user-add" || *action == "user-role"
	if needsRole != (*role != "") || (needsRole && !adminauth.Role(*role)) {
		return errors.New("-role Admin or ReadOnly is required only for user-add or user-role")
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
	var password string
	if *action == "user-add" || *action == "user-password" {
		value, err := secretinput.Password(true)
		if err != nil {
			return err
		}
		password = value
	}
	s, err := state.Open(*dir)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	switch *action {
	case "sessions-revoke-all":
		return s.RevokeAllSessions(ctx)
	case "users":
		users, err := s.Users(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(users)
	case "user-add":
		user, err := s.CreateUser(ctx, *username, *role, password)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(user)
	case "user-password":
		return s.ChangeUser(ctx, *username, "password", password)
	case "user-role":
		return s.ChangeUser(ctx, *username, "role", *role)
	case "user-disable":
		return s.ChangeUser(ctx, *username, "disable", "")
	case "user-revoke":
		return s.ChangeUser(ctx, *username, "revoke", "")
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
