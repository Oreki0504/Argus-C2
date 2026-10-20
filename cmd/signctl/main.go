// signctl prepares local signing keys and public trust artifacts. It has no
// network, service-control, state-reset, or active-installation operation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, errUnhealthy) {
			os.Exit(2)
		}
		log.Fatal(err)
	}
}

var errUnhealthy = errors.New("signer health requires attention")

func run(args []string, writer io.Writer) error {
	flags := flag.NewFlagSet("signctl", flag.ContinueOnError)
	action := flags.String("action", "", "generate, stage, retire, or inspect")
	out := flags.String("out", "", "new key directory for generate, or new JSON file for stage/retire")
	current := flags.String("current", "", "current public PEM key or trust-set JSON")
	next := flags.String("next-public-key", "", "next public PEM key; stage only")
	retire := flags.String("retire-at", "", "old key cutoff as RFC3339; stage only")
	until := flags.String("valid-until", "", "new key expiry as RFC3339; stage only")
	id := flags.String("key-id", "", "key to remove; retire only")
	selected := flags.String("selected-key-id", "", "expected active key ID; inspect only")
	warning := flags.Duration("warn-before", 10*24*time.Hour, "expiry warning window, 0 through 2160h; inspect only")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	allowed := map[string]map[string]bool{
		"generate": {"action": true, "out": true},
		"stage":    {"action": true, "out": true, "current": true, "next-public-key": true, "retire-at": true, "valid-until": true},
		"retire":   {"action": true, "out": true, "current": true, "key-id": true},
		"inspect":  {"action": true, "current": true, "selected-key-id": true, "warn-before": true},
	}
	bad := allowed[*action] == nil || flags.NArg() != 0
	flags.Visit(func(f *flag.Flag) {
		if !allowed[*action][f.Name] {
			bad = true
		}
	})
	if bad {
		return errors.New("unknown action or incompatible flags")
	}
	if *action == "inspect" {
		if *current == "" {
			return errors.New("current local trust is required")
		}
		report, err := signing.Inspect(*current, *selected, *warning, time.Now())
		if err != nil {
			return err
		}
		if err := json.NewEncoder(writer).Encode(report); err != nil {
			return err
		}
		if report.State != "ok" {
			return errUnhealthy
		}
		return nil
	}
	if *out == "" {
		return errors.New("required: -action and -out; no positional arguments")
	}
	if *action == "generate" {
		if *current != "" || *next != "" || *retire != "" || *until != "" || *id != "" {
			return errors.New("generate accepts only -out")
		}
		return signing.Generate(*out)
	}
	if *current == "" {
		return errors.New("current local trust is required")
	}
	legacy, previous, err := signing.LoadVerification(*current)
	if err != nil {
		return err
	}
	var trust signing.TrustSet
	switch *action {
	case "stage":
		if *next == "" || *retire == "" || *until == "" || *id != "" {
			return errors.New("stage requires next key, retire-at, and valid-until")
		}
		key, err := signing.LoadPublic(*next)
		if err != nil {
			return err
		}
		cutoff, err := time.Parse(time.RFC3339, *retire)
		if err != nil {
			return err
		}
		expiry, err := time.Parse(time.RFC3339, *until)
		if err != nil {
			return err
		}
		trust, err = signing.Stage(legacy, previous, key, time.Now(), cutoff.Unix(), expiry.Unix())
		if err != nil {
			return err
		}
	case "retire":
		if previous == nil || *id == "" || *next != "" || *retire != "" || *until != "" {
			return errors.New("retire requires a current trust set and key ID only")
		}
		trust, err = signing.Retire(*previous, *id)
		if err != nil {
			return err
		}
	default:
		return errors.New("unknown signer action")
	}
	data, err := trust.Canonical()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}
