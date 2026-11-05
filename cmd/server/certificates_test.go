package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
)

func TestCertificateMonitorReadsPublicFilesAndSignalsExpiry(t *testing.T) {
	for _, status := range []string{"ok", "expiring", "expired", "not_yet_valid"} {
		t.Run(status, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			c := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
			switch status {
			case "expiring":
				c.NotAfter = now.Add(24 * time.Hour)
			case "expired":
				c.NotAfter = now.Add(-time.Minute)
			case "not_yet_valid":
				c.NotBefore = now.Add(time.Hour)
			}
			der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			certPath := filepath.Join(dir, "cert.pem")
			if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			missing := filepath.Join(dir, "not-present")
			file := filepath.Join(dir, "server.json")
			if err = writeJSON(file, config.Server{Listen: "127.0.0.1:8443", StateDir: missing, Certificate: certPath, CA: certPath, PrivateKey: missing, IssuerKey: missing, Admins: missing}); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = certificatesCommand([]string{"-config", file}, &out)
			if (err == nil) != (status == "ok") {
				t.Fatal(status, err)
			}
			var report struct {
				Certificates []certificateObservation `json:"certificates"`
			}
			if e := json.Unmarshal(out.Bytes(), &report); e != nil || len(report.Certificates) != 2 {
				t.Fatal(report, e)
			}
			for _, c := range report.Certificates {
				if c.Status != status || c.Fingerprint == "" {
					t.Fatal(c)
				}
			}
		})
	}
}
