package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
)

type certificateObservation struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	NotBefore   int64  `json:"not_before"`
	NotAfter    int64  `json:"not_after"`
	Status      string `json:"status"`
}

func certificatesCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("certificates", flag.ContinueOnError)
	file := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	warn := f.Duration("warn-before", 30*24*time.Hour, "warn before certificate expiry, 1h to 8760h")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *warn < time.Hour || *warn > 365*24*time.Hour {
		return errors.New("invalid certificate check arguments")
	}
	c, err := config.LoadServer(*file)
	if err != nil {
		return err
	}
	now := time.Now()
	report := struct {
		CheckedAt    int64                    `json:"checked_at"`
		Certificates []certificateObservation `json:"certificates"`
	}{CheckedAt: now.Unix(), Certificates: []certificateObservation{}}
	warning := false
	for _, entry := range []struct{ name, path string }{{"server", c.Certificate}, {"issuer", c.CA}} {
		b, err := localfile.Read(entry.path, 65536, false)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("invalid certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		status := "ok"
		switch {
		case now.Before(cert.NotBefore):
			status = "not_yet_valid"
		case !now.Before(cert.NotAfter):
			status = "expired"
		case cert.NotAfter.Sub(now) <= *warn:
			status = "expiring"
		}
		if status != "ok" {
			warning = true
		}
		report.Certificates = append(report.Certificates, certificateObservation{Name: entry.name, Fingerprint: identity.Fingerprint(cert), NotBefore: cert.NotBefore.Unix(), NotAfter: cert.NotAfter.Unix(), Status: status})
	}
	if err = json.NewEncoder(out).Encode(report); err != nil {
		return err
	}
	if warning {
		return errors.New("certificate validity requires operator attention")
	}
	return nil
}
