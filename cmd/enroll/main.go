// enroll performs an explicit one-time enrollment using a token on stdin.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

func main() {
	log.SetFlags(0)
	server := flag.String("server", "https://127.0.0.1:8444", "enrollment HTTPS origin")
	ca := flag.String("ca", "", "preinstalled server and issuer root CA bundle")
	out := flag.String("out", "", "new private probe state directory")
	flag.Parse()
	if flag.NArg() != 0 || *ca == "" || *out == "" {
		log.Fatal("required: -ca, -out; token must arrive on stdin, not the command line")
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		log.Fatal("enrollment must run as the non-root probe user")
	}
	token, err := strictjson.Read(os.Stdin, 128)
	if err != nil {
		log.Fatal("could not read a bounded enrollment token from stdin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	n, err := agent.Enroll(ctx, *server, *ca, strings.TrimSpace(string(token)), *out)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(n); err != nil {
		log.Fatal(err)
	}
}
