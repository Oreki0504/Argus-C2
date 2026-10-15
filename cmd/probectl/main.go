// probectl explicitly initializes local replay state or reads its audit chain.
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

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	action := flag.String("action", "audit", "init, trust-migrate, or audit")
	dir := flag.String("state", "", "private probe state directory; init requires a new directory")
	identityFile := flag.String("identity", "", "enrolled local identity for initialization")
	keyFile := flag.String("task-public-key", "", "current local PEM key or trust-set JSON")
	nextTrust := flag.String("next-trust-set", "", "reviewed next trust-set JSON; trust-migrate only")
	after := flag.Int64("after", 0, "audit sequence cursor")
	limit := flag.Int("limit", 100, "page size, 1 through 200")
	flag.Parse()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return errors.New("run probectl as the non-root probe user")
	}
	if flag.NArg() != 0 || *dir == "" {
		return errors.New("required: -state; no positional arguments")
	}
	if (*action == "trust-migrate") != (*nextTrust != "") {
		return errors.New("-next-trust-set is required only for trust-migrate")
	}
	switch *action {
	case "init", "trust-migrate":
		if *identityFile == "" || *keyFile == "" {
			return errors.New("initialization requires -identity and -task-public-key")
		}
		n, err := identity.LoadNode(*identityFile)
		if err != nil {
			return err
		}
		key, trust, err := signing.LoadVerification(*keyFile)
		if err != nil {
			return err
		}
		if *action == "init" {
			if trust != nil {
				return probe.InitializeWithTrust(*dir, n, *trust)
			}
			return probe.Initialize(*dir, n, key)
		}
		next, err := signing.LoadTrust(*nextTrust)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return probe.MigrateTrust(ctx, *dir, n, key, trust, next)
	case "audit":
		if *identityFile != "" || *keyFile != "" {
			return errors.New("identity and task key flags apply only to initialization")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		page, err := probe.ReadAudit(ctx, *dir, *after, *limit)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(page)
	default:
		return errors.New("unknown local action")
	}
}
