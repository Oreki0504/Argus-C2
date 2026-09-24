// devsign creates a separate, locally distributed development task-signing key.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/Oreki0504/Argus-C2/internal/signing"
)

func main() {
	log.SetFlags(0)
	out := flag.String("out", ".local/task-signing", "new private directory for task-signing keys")
	flag.Parse()
	if flag.NArg() != 0 || *out == "" {
		log.Fatal("expected -out DIRECTORY and no positional arguments")
	}
	if err := signing.Generate(*out); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created task-private.pem and task-public.pem in %s. Distribute only the public key to probes.\n", *out)
}
