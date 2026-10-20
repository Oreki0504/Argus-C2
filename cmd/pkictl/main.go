// pkictl performs local offline issuance and credential inspection only.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/pki"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}
func run(args []string, writer io.Writer) (int, error) {
	flags := flag.NewFlagSet("pkictl", flag.ContinueOnError)
	action := flags.String("action", "", "root, request, issue, or inspect")
	out := flags.String("out", "", "new output directory; never overwritten")
	profile := flags.String("profile", "", "issuer/server for issue; root/issuer/server/client for inspect")
	lifetime := flags.Duration("lifetime", 0, "explicit issuance lifetime; defaults: root 5 years, issuer 365 days, server 90 days")
	rootCert := flags.String("root-cert", "", "offline root certificate; issue only")
	rootKey := flags.String("root-key", "", "offline root private key; issue only")
	csr := flags.String("csr", "", "public CSR PEM; issue only")
	cert := flags.String("cert", "", "certificate PEM; inspect only")
	key := flags.String("key", "", "optional matching private key; inspect only")
	ca := flags.String("ca", "", "explicit trust bundle; inspect only")
	name := flags.String("server-name", "", "expected TLS server name; server inspection only")
	nodeFile := flags.String("identity", "", "expected node identity; client inspection only")
	warning := flags.Duration("warn-before", 10*24*time.Hour, "expiry warning window, 0 through 2160h; inspect only")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, err
	}
	allowed := map[string]map[string]bool{
		"root":    {"action": true, "out": true, "lifetime": true},
		"request": {"action": true, "out": true},
		"issue":   {"action": true, "out": true, "profile": true, "lifetime": true, "root-cert": true, "root-key": true, "csr": true},
		"inspect": {"action": true, "profile": true, "cert": true, "key": true, "ca": true, "server-name": true, "identity": true, "warn-before": true},
	}
	bad := flags.NArg() != 0 || allowed[*action] == nil
	flags.Visit(func(f *flag.Flag) {
		if !allowed[*action][f.Name] {
			bad = true
		}
	})
	if bad {
		return 1, errors.New("unknown action or flags incompatible with action")
	}
	if *action != "inspect" && *out == "" {
		return 1, errors.New("new output directory required")
	}
	var err error
	switch *action {
	case "root":
		err = pki.CreateRoot(*out, *lifetime)
	case "request":
		err = pki.PrepareRequest(*out)
	case "issue":
		if *rootCert == "" || *rootKey == "" || *csr == "" {
			return 1, errors.New("issue requires root-cert, root-key and csr")
		}
		_, err = pki.Issue(*rootCert, *rootKey, *csr, *profile, *out, *lifetime)
	case "inspect":
		if *cert == "" || *ca == "" || (*profile == "server") != (*name != "") || (*profile == "client") != (*nodeFile != "") {
			return 1, errors.New("inspect requires cert, ca, profile and only its matching server-name or identity")
		}
		opts := tlsconfig.HealthOptions{Profile: *profile, ServerName: *name, WarnBefore: *warning}
		if *nodeFile != "" {
			n, err := identity.LoadNode(*nodeFile)
			if err != nil {
				return 1, err
			}
			opts.Node = &n
		}
		report, err := tlsconfig.Inspect(tlsconfig.Files{Certificate: *cert, PrivateKey: *key, CA: *ca}, opts)
		if err != nil {
			return 1, err
		}
		if err := json.NewEncoder(writer).Encode(report); err != nil {
			return 1, err
		}
		if report.State != "ok" {
			return 2, nil
		}
		return 0, nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}
