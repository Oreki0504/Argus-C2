package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

type renewalPlan struct {
	Version  int                     `json:"version"`
	Origin   string                  `json:"origin"`
	CAHash   string                  `json:"ca_sha256"`
	Node     identity.Node           `json:"node"`
	Previous string                  `json:"previous_certificate_sha256"`
	Request  protocol.RenewalRequest `json:"request"`
}

func renewalClient(address string, files tlsconfig.Files, n identity.Node) (*Client, string, error) {
	u, err := ServerURL(address)
	if err != nil {
		return nil, "", err
	}
	ca, err := localfile.Read(files.CA, 64*1024, false)
	if err != nil {
		return nil, "", err
	}
	config, err := tlsconfig.Client(files, n, u.Hostname())
	if err != nil {
		return nil, "", err
	}
	c, err := NewClient(address, config, n)
	return c, audit.Digest(ca), err
}

// PrepareRenewal writes a new private key and a durable request before any
// network operation. The operator chooses the directory; no server path is used.
func PrepareRenewal(address string, files tlsconfig.Files, n identity.Node, dir string) error {
	c, caHash, err := renewalClient(address, files, n)
	if err != nil {
		return err
	}
	defer c.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	plan := renewalPlan{Version: 1, Origin: c.origin, CAHash: caHash, Node: n, Previous: identity.Fingerprint(c.credential), Request: protocol.RenewalRequest{Version: 1, RenewalID: identity.RandomID(), CSR: base64.RawURLEncoding.EncodeToString(csr)}}
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "probe-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "renewal.json"), data); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return syncDir(filepath.Dir(dir))
}

func (c *Client) RenewCertificate(ctx context.Context, req protocol.RenewalRequest, keyPEM []byte) (protocol.RenewalResponse, error) {
	bad := protocol.RenewalResponse{}
	data, err := json.Marshal(req)
	if err != nil {
		return bad, err
	}
	_, der, err := protocol.DecodeRenewalRequest(data)
	if err != nil {
		return bad, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return bad, errors.New("invalid staged CSR")
	}
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return bad, errors.New("invalid staged key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return bad, errors.New("invalid staged key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return bad, errors.New("expected staged Ed25519 key")
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(public, csr.RawSubjectPublicKeyInfo) {
		return bad, errors.New("staged CSR and key mismatch")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+protocol.RenewalPath, bytes.NewReader(data))
	if err != nil {
		return bad, err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return bad, errors.New("renewal transport failed; retain staged request for an explicit retry")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return bad, errors.New("server rejected renewal; retain staged request and inspect credential state")
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return bad, errors.New("expected JSON renewal response")
	}
	data, err = strictjson.Read(response.Body, protocol.MaxRenewalBytes)
	if err != nil {
		return bad, err
	}
	result, err := protocol.DecodeRenewalResponse(data)
	if err != nil {
		return bad, err
	}
	if result.RenewalID != req.RenewalID || result.AgentID != c.node.AgentID || result.Epoch != c.node.EnrollmentEpoch || result.PreviousSHA256 != identity.Fingerprint(c.credential) || result.PreviousValidUntil > c.credential.NotAfter.Unix() || result.PreviousValidUntil > time.Now().Add(24*time.Hour+time.Minute).Unix() {
		return bad, errors.New("renewal response binding mismatch")
	}
	if err := verifyEnrollmentCertificate(result.CertificatePEM, keyPEM, c.node, c.roots); err != nil {
		return bad, err
	}
	block, _ := pem.Decode([]byte(result.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || result.PreviousValidUntil > leaf.NotAfter.Unix() {
		return bad, errors.New("invalid renewal overlap")
	}
	return result, nil
}

// RequestRenewal may be retried with exactly the same private staging directory
// and still-valid old credential. It never changes the active files or replay DB.
func RequestRenewal(ctx context.Context, address string, files tlsconfig.Files, n identity.Node, dir string) (protocol.RenewalResponse, error) {
	bad := protocol.RenewalResponse{}
	st, err := os.Lstat(dir)
	if err != nil {
		return bad, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return bad, errors.New("renewal staging directory must be private and operator-controlled")
	}
	lock, err := localdb.Lock(dir)
	if err != nil {
		return bad, err
	}
	defer lock.Close()
	data, err := localfile.Read(filepath.Join(dir, "renewal.json"), 8192, true)
	if err != nil {
		return bad, err
	}
	var raw struct {
		Version  int             `json:"version"`
		Origin   string          `json:"origin"`
		CAHash   string          `json:"ca_sha256"`
		Node     json.RawMessage `json:"node"`
		Previous string          `json:"previous_certificate_sha256"`
		Request  json.RawMessage `json:"request"`
	}
	if err := strictjson.Decode(data, &raw, 8192, "version", "origin", "ca_sha256", "node", "previous_certificate_sha256", "request"); err != nil {
		return bad, err
	}
	node, err := identity.Decode(raw.Node)
	if err != nil {
		return bad, err
	}
	request, _, err := protocol.DecodeRenewalRequest(raw.Request)
	if err != nil {
		return bad, err
	}
	plan := renewalPlan{Version: raw.Version, Origin: raw.Origin, CAHash: raw.CAHash, Node: node, Previous: raw.Previous, Request: request}
	c, caHash, err := renewalClient(address, files, n)
	if err != nil {
		return bad, err
	}
	defer c.Close()
	if plan.Version != 1 || plan.Origin != c.origin || plan.CAHash != caHash || plan.Node != n || plan.Previous != identity.Fingerprint(c.credential) {
		return bad, errors.New("staged renewal belongs to different credentials, trust, or server")
	}
	keyPEM, err := localfile.Read(filepath.Join(dir, "probe-key.pem"), 16384, true)
	if err != nil {
		return bad, err
	}
	result, err := c.RenewCertificate(ctx, plan.Request, keyPEM)
	if err != nil {
		return bad, err
	}
	data, err = json.Marshal(result)
	if err != nil {
		return bad, err
	}
	if err := saveRenewalFile(dir, "probe-cert.pem", []byte(result.CertificatePEM)); err != nil {
		return bad, err
	}
	if err := saveRenewalFile(dir, "renewal-response.json", data); err != nil {
		return bad, err
	}
	data, err = json.Marshal(n)
	if err != nil {
		return bad, err
	}
	// The existing identity file remains the last, durable completion marker.
	if err := saveRenewalFile(dir, "identity.json", data); err != nil {
		return bad, err
	}
	return result, nil
}

// Called under the staging-directory process lock. A private temporary file
// keeps interrupted writes from creating a partial completion marker. Existing
// completed files must match byte-for-byte and are never replaced.
func saveRenewalFile(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	if _, err := os.Lstat(path); err == nil {
		current, err := localfile.Read(path, protocol.MaxRenewalBytes, true)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, data) {
			return errors.New("existing staged output differs; preserve it for local review")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(dir, ".renewal-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}
