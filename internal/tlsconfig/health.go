package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

type CertificateHealth struct {
	Fingerprint      string `json:"certificate_sha256"`
	NotBefore        int64  `json:"not_before"`
	NotAfter         int64  `json:"not_after"`
	RemainingSeconds int64  `json:"remaining_seconds"`
	State            string `json:"state"`
	TrustAnchor      bool   `json:"trust_anchor"`
}
type HealthReport struct {
	Version      int                 `json:"version"`
	CheckedAt    int64               `json:"checked_at"`
	Profile      string              `json:"profile"`
	State        string              `json:"state"`
	Issues       []string            `json:"issues"`
	Certificates []CertificateHealth `json:"certificates"`
}
type HealthOptions struct {
	Profile, ServerName string
	Node                *identity.Node
	WarnBefore          time.Duration
	Now                 time.Time
}

// Inspect is a local snapshot, not a registry/revocation check or a network
// readiness assertion. It never reads a private key unless explicitly supplied.
func Inspect(files Files, opts HealthOptions) (HealthReport, error) {
	r := HealthReport{Version: 1, Profile: opts.Profile, State: "ok", Issues: []string{}, Certificates: []CertificateHealth{}}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	r.CheckedAt = opts.Now.Unix()
	if opts.WarnBefore < 0 || opts.WarnBefore > 90*24*time.Hour {
		return r, errors.New("warning window must be 0 through 90 days")
	}
	if opts.Profile != "root" && opts.Profile != "issuer" && opts.Profile != "server" && opts.Profile != "client" {
		return r, errors.New("unknown certificate profile")
	}
	certs, err := LoadCertificates(files.Certificate)
	if err != nil {
		return r, err
	}
	anchors, err := LoadCertificates(files.CA)
	if err != nil {
		return r, err
	}
	roots, err := certificateRoots(anchors)
	if err != nil {
		return r, err
	}
	issue := func(code string) { r.State = "blocked"; r.Issues = append(r.Issues, code) }
	seen := map[string]bool{}
	for _, group := range []struct {
		certs  []*x509.Certificate
		anchor bool
	}{{anchors, true}, {certs, false}} {
		for _, cert := range group.certs {
			fp := identity.Fingerprint(cert)
			if seen[fp] {
				continue
			}
			seen[fp] = true
			state := "ok"
			switch {
			case opts.Now.Before(cert.NotBefore):
				state = "not_yet_valid"
			case !opts.Now.Before(cert.NotAfter):
				state = "expired"
			case !opts.Now.Add(opts.WarnBefore).Before(cert.NotAfter):
				state = "expiring"
			}
			if state != "ok" && r.State == "ok" {
				r.State = "warning"
			}
			r.Certificates = append(r.Certificates, CertificateHealth{fp, cert.NotBefore.Unix(), cert.NotAfter.Unix(), cert.NotAfter.Unix() - opts.Now.Unix(), state, group.anchor})
		}
	}
	leaf := certs[0]
	usage := x509.ExtKeyUsageClientAuth
	if opts.Profile == "server" {
		usage = x509.ExtKeyUsageServerAuth
	}
	switch opts.Profile {
	case "root":
		if len(certs) != 1 || !leaf.IsCA || !bytes.Equal(leaf.RawSubject, leaf.RawIssuer) || leaf.CheckSignatureFrom(leaf) != nil {
			issue("invalid_root_profile")
		}
		found := false
		for _, c := range anchors {
			found = found || bytes.Equal(c.Raw, leaf.Raw)
		}
		if !found {
			issue("root_not_in_explicit_bundle")
		}
		usage = x509.ExtKeyUsageAny
	case "issuer":
		if len(certs) != 1 || CheckIssuerProfile(leaf) != nil {
			issue("invalid_issuer_profile")
		}
	default:
		if leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != usage || len(leaf.UnknownExtKeyUsage) != 0 {
			issue("invalid_leaf_profile")
		}
		if opts.Profile == "server" && opts.ServerName == "" {
			return r, errors.New("server health requires an expected server name")
		}
		if opts.Profile == "client" {
			n, err := identity.FromCertificate(leaf)
			if err != nil || opts.Node == nil || n != *opts.Node {
				issue("client_identity_mismatch")
			}
		}
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: opts.Now, KeyUsages: []x509.ExtKeyUsage{usage}, DNSName: opts.ServerName})
	if err != nil || len(chains) == 0 {
		issue("chain_or_name_invalid")
	} else {
		if opts.Profile == "issuer" && len(chains[0]) < 2 {
			issue("issuer_is_trust_anchor")
		}
		for _, cert := range chains[0] {
			if opts.Now.Before(cert.NotBefore) || !opts.Now.Before(cert.NotAfter) {
				issue("chain_outside_validity_window")
				break
			}
		}
	}
	if files.PrivateKey != "" {
		secret, err := localfile.Read(files.PrivateKey, 16*1024, true)
		if err != nil {
			return r, err
		}
		var public []byte
		for _, cert := range certs {
			public = append(public, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		}
		if _, err := tls.X509KeyPair(public, secret); err != nil {
			issue("private_key_mismatch")
		}
	}
	return r, nil
}
