// devpki provisions local test credentials; it is not an enrollment service.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
)

func main() {
	log.SetFlags(0)
	out := flag.String("out", ".local/dev-pki", "new directory for 24-hour local development credentials")
	flag.Parse()
	if flag.NArg() != 0 || *out == "" {
		log.Fatal("expected -out DIRECTORY and no positional arguments")
	}
	bundle, err := devpki.New()
	if err != nil {
		log.Fatal(err)
	}
	if err := bundle.WriteDir(*out); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created local development credentials in %s (valid for 24 hours).\n", *out)
	fmt.Println("The CA private key was not saved. Do not use these credentials in production.")
}
