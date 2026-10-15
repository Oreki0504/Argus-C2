// signctl prepares local signing keys and public trust artifacts. It has no
// network, service-control, state-reset, or active-installation operation.
package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	action := flag.String("action", "", "generate, stage, or retire")
	out := flag.String("out", "", "new key directory for generate, or new JSON file for stage/retire")
	current := flag.String("current", "", "current public PEM key or trust-set JSON")
	next := flag.String("next-public-key", "", "next public PEM key; stage only")
	retire := flag.String("retire-at", "", "old key cutoff as RFC3339; stage only")
	until := flag.String("valid-until", "", "new key expiry as RFC3339; stage only")
	id := flag.String("key-id", "", "key to remove; retire only")
	flag.Parse()
	if flag.NArg() != 0 || *out == "" {
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
