package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

// Enroll creates a new state directory and writes the private key before any
// request. An ambiguous failure deliberately leaves this directory untouched.
// Never automatically replay enrollment or overwrite an existing identity.
func Enroll(ctx context.Context, address, caPath, token, dir string) (identity.Node, error) {
	u, err := ServerURL(address)
	if err != nil {
		return identity.Node{}, err
	}
	if !identity.Hex(token, 64) {
		return identity.Node{}, errors.New("invalid enrollment token")
	}
	config, err := tlsconfig.EnrollmentClient(caPath, u.Hostname())
	if err != nil {
		return identity.Node{}, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return identity.Node{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return identity.Node{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return identity.Node{}, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return identity.Node{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeNew(filepath.Join(dir, "probe-key.pem"), keyPEM); err != nil {
		return identity.Node{}, err
	}
	if err := syncDir(dir); err != nil {
		return identity.Node{}, err
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return identity.Node{}, err
	}
	request := protocol.EnrollmentRequest{Version: protocol.Version, Token: token, CSR: base64.RawURLEncoding.EncodeToString(csr)}
	data, err := json.Marshal(request)
	if err != nil {
		return identity.Node{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String()+"/api/v1/enroll", bytes.NewReader(data))
	if err != nil {
		return identity.Node{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := newHTTP(config)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return identity.Node{}, errors.New("enrollment transport failed; inspect local state before retrying")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return identity.Node{}, errors.New("server rejected enrollment")
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return identity.Node{}, errors.New("expected JSON enrollment response")
	}
	data, err = strictjson.Read(resp.Body, protocol.MaxEnrollmentBytes)
	if err != nil {
		return identity.Node{}, err
	}
	r, err := protocol.DecodeEnrollmentResponse(data)
	if err != nil {
		return identity.Node{}, errors.New("invalid enrollment response")
	}
	n := identity.Node{AgentID: r.AgentID, EnrollmentEpoch: r.EnrollmentEpoch}
	if err := verifyEnrollmentCertificate(r.CertificatePEM, keyPEM, n, config.RootCAs); err != nil {
		return identity.Node{}, err
	}
	if err := writeNew(filepath.Join(dir, "probe-cert.pem"), []byte(r.CertificatePEM)); err != nil {
		return identity.Node{}, err
	}
	data, err = json.Marshal(n)
	if err != nil {
		return identity.Node{}, err
	}
	// identity.json is the final completion marker for the credential bundle.
	if err := writeNew(filepath.Join(dir, "identity.json"), data); err != nil {
		return identity.Node{}, err
	}
	if err := syncDir(dir); err != nil {
		return identity.Node{}, err
	}
	return n, nil
}

func verifyEnrollmentCertificate(certPEM string, keyPEM []byte, n identity.Node, roots *x509.CertPool) error {
	pair, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil || len(pair.Certificate) != 2 {
		return errors.New("invalid or mismatched issued certificate chain")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	actual, err := identity.FromCertificate(leaf)
	if err != nil || actual != n || leaf.NotAfter.After(time.Now().Add(12*time.Hour+time.Minute)) {
		return errors.New("issued certificate has unexpected identity or lifetime")
	}
	intermediate, err := x509.ParseCertificate(pair.Certificate[1])
	if err != nil {
		return err
	}
	if !intermediate.IsCA || !intermediate.MaxPathLenZero || len(intermediate.ExtKeyUsage) != 1 || intermediate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(intermediate.UnknownExtKeyUsage) != 0 {
		return errors.New("invalid issuing CA scope")
	}
	pool := x509.NewCertPool()
	pool.AddCert(intermediate)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return errors.New("issued certificate failed trusted chain verification")
	}
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
