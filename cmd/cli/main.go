// cli is the authenticated HTTPS administration client. Local account recovery
// belongs to localctl on the server; this program never opens the server DB.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/adminclient"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/secretinput"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	action := flag.String("action", "me", "login, logout, revoke, forget, me, agents, agent, tasks, task, audit, submit, token, or disable")
	origin := flag.String("server", "", "administrator HTTPS origin")
	ca := flag.String("ca", "", "manually trusted server CA PEM")
	sessionDir := flag.String("session", "", "explicit private local session directory")
	username := flag.String("username", "", "user name; login only")
	nodeID := flag.String("agent-id", "", "node ID; agent, submit, or disable only")
	requestID := flag.String("request-id", "", "request ID; task only")
	kind := flag.String("type", "", "fixed task type; submit only")
	profileID := flag.String("profile-id", "", "local SSH profile ID; ssh.audit only")
	serviceID := flag.String("service-id", "", "local service ID; service.status only")
	after := flag.String("after", "", "page cursor; agents, tasks, or audit only")
	limit := flag.Int("limit", 50, "page size, 1 through 50")
	ttl := flag.Int("ttl-seconds", 120, "task lifetime 1-300 seconds, or enrollment token lifetime 1-900 seconds")
	flag.Parse()
	if flag.NArg() != 0 || *sessionDir == "" {
		return errors.New("-session is required; no positional arguments")
	}
	valid := map[string]bool{"login": true, "logout": true, "revoke": true, "forget": true, "me": true, "agents": true, "agent": true, "tasks": true, "task": true, "audit": true, "submit": true, "token": true, "disable": true}
	if !valid[*action] {
		return errors.New("unknown administrator action")
	}
	if (*action == "login") != (*username != "") || (*username != "" && !adminauth.Username(*username)) {
		return errors.New("-username is required only for login")
	}
	needsNode := *action == "agent" || *action == "submit" || *action == "disable"
	if needsNode != (*nodeID != "") || (*nodeID != "" && !identity.Hex(*nodeID, 32)) {
		return errors.New("valid -agent-id is required only for agent, submit, or disable")
	}
	if (*action == "task") != (*requestID != "") || (*requestID != "" && !identity.Hex(*requestID, 32)) {
		return errors.New("valid -request-id is required only for task")
	}
	if (*action == "submit") != (*kind != "") {
		return errors.New("-type is required only for submit")
	}
	params := json.RawMessage(`{}`)
	if *action == "submit" {
		if !protocol.KnownTask(protocol.TaskType(*kind)) || *ttl < 1 || *ttl > 300 {
			return errors.New("invalid task type or lifetime")
		}
		switch protocol.TaskType(*kind) {
		case protocol.SSHAudit:
			if !protocol.ResourceID(*profileID) || *serviceID != "" {
				return errors.New("ssh.audit requires only -profile-id")
			}
			params, _ = json.Marshal(map[string]string{"profile_id": *profileID})
		case protocol.ServiceStatus:
			if !protocol.ResourceID(*serviceID) || *profileID != "" {
				return errors.New("service.status requires only -service-id")
			}
			params, _ = json.Marshal(map[string]string{"service_id": *serviceID})
		default:
			if *profileID != "" || *serviceID != "" {
				return errors.New("system tasks have no resource selector")
			}
		}
	} else if *profileID != "" || *serviceID != "" {
		return errors.New("resource selectors require submit")
	}
	paging := *action == "agents" || *action == "tasks" || *action == "audit"
	if !paging && *after != "" || *limit < 1 || *limit > 50 {
		return errors.New("invalid page arguments")
	}
	query := "?limit=" + strconv.Itoa(*limit)
	if *after != "" {
		if *action == "agents" {
			if !identity.Hex(*after, 32) {
				return errors.New("invalid node cursor")
			}
		} else {
			v, err := strconv.ParseInt(*after, 10, 64)
			if err != nil || v < 0 || strconv.FormatInt(v, 10) != *after {
				return errors.New("invalid sequence cursor")
			}
		}
		query += "&after=" + *after
	}
	if *action == "forget" {
		return adminclient.ForgetSession(*sessionDir)
	}
	if *origin == "" || *ca == "" {
		return errors.New("-server and -ca are required")
	}
	client, err := adminclient.New(*origin, *ca)
	if err != nil {
		return err
	}
	defer client.Close()
	if *action == "login" {
		if err := adminclient.PrepareSession(*sessionDir); err != nil {
			return err
		}
		password, err := secretinput.Password(false)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		login, err := client.Login(ctx, *username, password)
		if err != nil {
			return err
		}
		if login.User.Username != *username {
			return errors.New("login returned a different user")
		}
		if err := client.SaveSession(*sessionDir, login); err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = client.Request(cleanup, login.Token, http.MethodPost, "/api/v1/auth/logout", []byte(`{}`))
			return fmt.Errorf("could not save session; server logout attempted: %w", err)
		}
		// Never print the bearer token or password.
		b, _ := json.Marshal(struct {
			User      any   `json:"user"`
			ExpiresAt int64 `json:"expires_at"`
		}{login.User, login.ExpiresAt})
		return output(b)
	}
	login, err := client.LoadSession(*sessionDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	method, path := http.MethodGet, "/api/v1/auth/me"
	var body []byte
	switch *action {
	case "logout", "revoke":
		method = http.MethodPost
		path = "/api/v1/auth/" + *action
		body = []byte(`{}`)
	case "agents":
		path = "/api/v1/agents" + query
	case "agent":
		path = "/api/v1/agents/" + *nodeID
	case "tasks":
		path = "/api/v1/tasks" + query
	case "task":
		path = "/api/v1/tasks/" + *requestID
	case "audit":
		path = "/api/v1/audit" + query
	case "disable":
		method = http.MethodPost
		path = "/api/v1/agents/" + *nodeID + "/disable"
		body = []byte(`{}`)
	case "token":
		if *ttl < 1 || *ttl > 900 {
			return errors.New("token lifetime must be 1-900 seconds")
		}
		method = http.MethodPost
		path = "/api/v1/enrollment-tokens"
		body, _ = json.Marshal(map[string]int{"ttl_seconds": *ttl})
	case "submit":
		method = http.MethodPost
		path = "/api/v1/tasks"
		body, _ = json.Marshal(struct {
			AgentID string          `json:"agent_id"`
			Type    string          `json:"task_type"`
			Params  json.RawMessage `json:"params"`
			TTL     int             `json:"ttl_seconds"`
		}{*nodeID, *kind, params, *ttl})
	}
	data, err := client.Request(ctx, login.Token, method, path, body)
	if err != nil {
		return err
	}
	if *action == "logout" || *action == "revoke" {
		if err := adminclient.ForgetSession(*sessionDir); err != nil {
			return fmt.Errorf("server session revoked; could not remove local session: %w", err)
		}
	}
	if *action == "token" {
		var r struct {
			Token     string `json:"token"`
			ExpiresAt int64  `json:"expires_at"`
		}
		if strictjson.Decode(data, &r, 256, "token", "expires_at") != nil || !identity.Hex(r.Token, 64) {
			return errors.New("invalid enrollment token response")
		}
		_, err = fmt.Fprintln(os.Stdout, r.Token)
		return err
	}
	return output(data)
}
func output(data []byte) error {
	// Re-encode JSON before terminal output, and escape non-ASCII code points so
	// node-supplied text cannot introduce terminal or bidirectional controls.
	var value any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return errors.New("invalid response JSON")
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	var out strings.Builder
	for _, r := range string(b) {
		if r <= 127 {
			out.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&out, "\\u%04x", r)
		} else {
			a, b := utf16.EncodeRune(r)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", a, b)
		}
	}
	_, err = fmt.Fprintln(os.Stdout, out.String())
	return err
}
