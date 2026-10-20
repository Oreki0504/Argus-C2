package pki_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/pki"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	return b
}

func TestOperationalIssuanceAndHealth(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "offline")
	must(t, pki.CreateRoot(root, 0))
	ca, key := filepath.Join(root, "root-cert.pem"), filepath.Join(root, "root-key.pem")
	before := read(t, key)
	if err := pki.CreateRoot(root, 0); err == nil {
		t.Fatal("overwrote root")
	}
	if !bytes.Equal(before, read(t, key)) {
		t.Fatal("changed existing key")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(key)
		must(t, err)
		if info.Mode().Perm() != 0600 {
			t.Fatal("root key permissions", info.Mode())
		}
		info, err = os.Stat(root)
		must(t, err)
		if info.Mode().Perm() != 0700 {
			t.Fatal("root directory permissions")
		}
	}
	issued := map[string]tlsconfig.Files{}
	for _, profile := range []string{"server", "issuer"} {
		req, out := filepath.Join(dir, profile+"-request"), filepath.Join(dir, profile+"-issued")
		must(t, pki.PrepareRequest(req))
		if err := pki.PrepareRequest(req); err == nil {
			t.Fatal("overwrote request")
		}
		receipt, err := pki.Issue(ca, key, filepath.Join(req, "request.pem"), profile, out, 0)
		must(t, err)
		var stored pki.Receipt
		must(t, json.Unmarshal(read(t, filepath.Join(out, "receipt.json")), &stored))
		if stored != receipt || receipt.Profile != profile || receipt.RootSHA256 == receipt.CertificateSHA256 {
			t.Fatal("wrong receipt")
		}
		entries, err := os.ReadDir(out)
		must(t, err)
		if len(entries) != 2 {
			t.Fatal("unexpected offline output")
		}
		if _, err := os.Stat(filepath.Join(out, "key.pem")); !os.IsNotExist(err) {
			t.Fatal("exported private key")
		}
		if _, err := pki.Issue(ca, key, filepath.Join(req, "request.pem"), profile, out, 0); err == nil {
			t.Fatal("overwrote issuance")
		}
		files := tlsconfig.Files{Certificate: filepath.Join(out, "certificate.pem"), PrivateKey: filepath.Join(req, "key.pem"), CA: ca}
		issued[profile] = files
		opts := tlsconfig.HealthOptions{Profile: profile, WarnBefore: 24 * time.Hour}
		if profile == "server" {
			opts.ServerName = "localhost"
		}
		report, err := tlsconfig.Inspect(files, opts)
		must(t, err)
		if report.State != "ok" {
			t.Fatal(profile, report)
		}
		certs, err := tlsconfig.LoadCertificates(files.Certificate)
		must(t, err)
		leaf := certs[0]
		if profile == "server" {
			if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" || len(leaf.IPAddresses) != 2 {
				t.Fatal("unexpected names")
			}
			if leaf.VerifyHostname("example.com") == nil {
				t.Fatal("non-loopback name accepted")
			}
		}
		for _, tc := range []struct {
			name  string
			now   time.Time
			state string
		}{
			{"warning", leaf.NotAfter.Add(-time.Hour), "warning"},
			{"exact expiry", leaf.NotAfter, "blocked"},
			{"expired", leaf.NotAfter.Add(time.Second), "blocked"},
			{"not yet valid", leaf.NotBefore.Add(-time.Second), "blocked"},
		} {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				opts.Now = tc.now
				r, err := tlsconfig.Inspect(files, opts)
				must(t, err)
				if r.State != tc.state {
					t.Fatalf("%s: %+v", tc.state, r)
				}
			})
		}
	}
	issuerFiles := issued["issuer"]
	issuer, err := enrollment.LoadIssuer(issuerFiles.Certificate, issuerFiles.PrivateKey, ca)
	must(t, err)
	must(t, issuer.SetLifetime(30*24*time.Hour))
	client := filepath.Join(dir, "client")
	must(t, pki.PrepareRequest(client))
	csr, err := pki.LoadRequest(filepath.Join(client, "request.pem"))
	must(t, err)
	node := identity.New()
	chain, leaf, err := issuer.Issue(csr, node)
	must(t, err)
	if remaining := time.Until(leaf.NotAfter); remaining < 30*24*time.Hour-time.Minute || remaining > 30*24*time.Hour {
		t.Fatal("30-day client lifetime", remaining)
	}
	certPath := filepath.Join(client, "certificate.pem")
	must(t, os.WriteFile(certPath, chain, 0600))
	clientFiles := tlsconfig.Files{Certificate: certPath, PrivateKey: filepath.Join(client, "key.pem"), CA: ca}
	report, err := tlsconfig.Inspect(clientFiles, tlsconfig.HealthOptions{Profile: "client", Node: &node})
	must(t, err)
	if report.State != "ok" {
		t.Fatal(report)
	}
	wrongNode := identity.New()
	report, err = tlsconfig.Inspect(clientFiles, tlsconfig.HealthOptions{Profile: "client", Node: &wrongNode})
	must(t, err)
	if report.State != "blocked" {
		t.Fatal("wrong identity accepted")
	}
	if err := issuer.CheckTransport(issuer.Certificate()); err == nil {
		t.Fatal("issuer/transport key reuse accepted")
	}
	serverCerts, err := tlsconfig.LoadCertificates(issued["server"].Certificate)
	must(t, err)
	must(t, issuer.CheckTransport(serverCerts[0]))
	for name, files := range map[string]tlsconfig.Files{
		"wrong key":  {Certificate: issued["server"].Certificate, PrivateKey: issuerFiles.PrivateKey, CA: ca},
		"wrong name": issued["server"],
	} {
		t.Run(name, func(t *testing.T) {
			serverName := "localhost"
			if name == "wrong name" {
				serverName = "example.com"
			}
			r, err := tlsconfig.Inspect(files, tlsconfig.HealthOptions{Profile: "server", ServerName: serverName})
			must(t, err)
			if r.State != "blocked" {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	rootHealth, err := tlsconfig.Inspect(tlsconfig.Files{Certificate: ca, CA: ca, PrivateKey: key}, tlsconfig.HealthOptions{Profile: "root"})
	must(t, err)
	if rootHealth.State != "ok" {
		t.Fatal(rootHealth)
	}
}

func TestIssuanceBoundaries(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	req := filepath.Join(dir, "request")
	must(t, pki.CreateRoot(root, 24*time.Hour))
	must(t, pki.PrepareRequest(req))
	ca, key, csr := filepath.Join(root, "root-cert.pem"), filepath.Join(root, "root-key.pem"), filepath.Join(req, "request.pem")
	for _, tc := range []struct {
		profile  string
		lifetime time.Duration
	}{{"client", 0}, {"root", 0}, {"server", 91 * 24 * time.Hour}, {"issuer", 366 * 24 * time.Hour}, {"server", time.Minute}, {"issuer", -time.Hour}, {"server", time.Hour + time.Nanosecond}} {
		if _, err := pki.Issue(ca, key, csr, tc.profile, filepath.Join(dir, "invalid"), tc.lifetime); err == nil {
			t.Fatal("invalid profile/lifetime", tc)
		}
	}
	r, err := pki.Issue(ca, key, csr, "issuer", filepath.Join(dir, "capped"), 0)
	must(t, err)
	roots, err := tlsconfig.LoadCertificates(ca)
	must(t, err)
	if r.NotAfter != roots[0].NotAfter.Unix() {
		t.Fatal("issuance exceeds root lifetime")
	}
	if _, err := pki.Issue(ca, filepath.Join(req, "key.pem"), csr, "server", filepath.Join(dir, "mismatch"), 0); err == nil {
		t.Fatal("wrong root key accepted")
	}
	for _, lifetime := range []time.Duration{time.Hour, 3651 * 24 * time.Hour, -time.Hour, 24*time.Hour + time.Nanosecond} {
		if err := pki.CreateRoot(filepath.Join(dir, "invalid-root"), lifetime); err == nil {
			t.Fatal("invalid root lifetime accepted")
		}
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "requested authority"}, DNSNames: []string{"example.com"}}, private)
	must(t, err)
	bad := filepath.Join(dir, "bad-csr")
	valid := read(t, csr)
	for _, data := range [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		append([]byte("prefix\n"), valid...),
		append(append([]byte{}, valid...), valid...),
		append([]byte("-----BEGIN CERTIFICATE REQUEST-----\nmalformed\n"), valid...),
		append(append([]byte{}, valid...), []byte("trailer")...),
		bytes.Repeat([]byte("x"), 4097),
	} {
		must(t, os.WriteFile(bad, data, 0600))
		if _, err := pki.LoadRequest(bad); err == nil {
			t.Fatal("accepted malformed or privileged CSR")
		}
	}
}
