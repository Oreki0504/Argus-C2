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
	enrollment := flag.Bool("enrollment", false, "provision a separate online client-certificate issuer for Phase 3")
	flag.Parse()
	if flag.NArg() != 0 || *out == "" {
		log.Fatal("expected -out DIRECTORY and no positional arguments")
	}
	var err error
	if *enrollment {
		var bundle *devpki.EnrollmentBundle
		bundle, err = devpki.NewEnrollment()
		if err == nil {
			err = bundle.WriteDir(*out)
		}
	} else {
		var bundle *devpki.Bundle
		bundle, err = devpki.New()
		if err == nil {
			err = bundle.WriteDir(*out)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created local development credentials in %s (valid for 24 hours).\n", *out)
	fmt.Println("The root CA private key was not saved. Do not use these credentials in production.")
}
