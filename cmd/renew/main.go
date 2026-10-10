// renew stages a new client TLS credential. Activation is local administration.
package main

import (
	"context"
	"encoding/json"
	"errors"
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	action := flag.String("action", "", "prepare, request, or verify")
	address := flag.String("server", "", "configured mTLS probe HTTPS origin")
	cert := flag.String("cert", "", "current client certificate PEM")
	key := flag.String("key", "", "current client private key PEM")
	ca := flag.String("ca", "", "locally installed CA PEM")
	id := flag.String("identity", "", "existing node identity JSON")
	out := flag.String("out", "", "private staging directory; new for prepare, existing for request")
	flag.Parse()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return errors.New("run renew as the non-root probe user with locally supplied credentials")
	}
	if flag.NArg() != 0 || *address == "" || *cert == "" || *key == "" || *ca == "" || *id == "" || (*action != "prepare" && *action != "request" && *action != "verify") || ((*action == "verify") != (*out == "")) {
		return errors.New("required: -action prepare|request|verify -server -cert -key -ca -identity; -out only for prepare/request; no positional arguments")
	}
	n, err := identity.LoadNode(*id)
	if err != nil {
		return err
	}
	files := tlsconfig.Files{Certificate: *cert, PrivateKey: *key, CA: *ca}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	switch *action {
	case "prepare":
		return agent.PrepareRenewal(*address, files, n, *out)
	case "request":
		r, err := agent.RequestRenewal(ctx, *address, files, n, *out)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(struct {
			AgentID            string `json:"agent_id"`
			Generation         int    `json:"generation"`
			PreviousValidUntil int64  `json:"previous_valid_until"`
		}{r.AgentID, r.Generation, r.PreviousValidUntil})
	default:
		u, err := agent.ServerURL(*address)
		if err != nil {
			return err
		}
		config, err := tlsconfig.Client(files, n, u.Hostname())
		if err != nil {
			return err
		}
		c, err := agent.NewClient(*address, config, n)
		if err != nil {
			return err
		}
		defer c.Close()
		info, err := c.Connect(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(info)
	}
}
