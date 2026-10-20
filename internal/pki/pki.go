// Package pki prepares operational PKI material through local administration.
// Only the offline issue command reads a root private key. Online services
// continue to use enrollment.Issuer and never import this package.
package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/signing"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

const RootLifetime = 5 * 365 * 24 * time.Hour
const IssuerLifetime = 365 * 24 * time.Hour
const ServerLifetime = 90 * 24 * time.Hour

type Receipt struct {
	Version           int    `json:"version"`
	Profile           string `json:"profile"`
	RootSHA256        string `json:"root_sha256"`
	CSRSHA256         string `json:"csr_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	NotBefore         int64  `json:"not_before"`
	NotAfter          int64  `json:"not_after"`
}

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}
func pemCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func privatePEM(key ed25519.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}

type output struct {
	name string
	data []byte
}

// The parent is selected and controlled by the local operator. Refuse every
// existing directory/file; leave partial preparation evidence on failure.
func writeBundle(dir string, files ...output) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for _, item := range files {
		f, err := os.OpenFile(filepath.Join(dir, item.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(item.data)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
	}
	return errors.Join(syncDirectory(dir), syncDirectory(filepath.Dir(dir)))
}

func CreateRoot(dir string, lifetime time.Duration) error {
	if lifetime == 0 {
		lifetime = RootLifetime
	}
	if lifetime < 24*time.Hour || lifetime > 10*365*24*time.Hour || lifetime%time.Second != 0 {
		return errors.New("root lifetime must be 1 through 3650 days in whole seconds")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	n, err := serial()
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "Argus-C2 offline root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	secret, err := privatePEM(key)
	if err != nil {
		return err
	}
	r := Receipt{Version: 1, Profile: "root", RootSHA256: identity.Fingerprint(cert), CertificateSHA256: identity.Fingerprint(cert), PublicKeySHA256: signing.KeyID(pub), NotBefore: cert.NotBefore.Unix(), NotAfter: cert.NotAfter.Unix()}
	receipt, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeBundle(dir, output{"root-key.pem", secret}, output{"root-cert.pem", pemCertificate(der)}, output{"receipt.json", receipt})
}

// PrepareRequest generates the key on its eventual server/issuer host. Its CSR
// contains no requested names, usages or attributes; the offline signer chooses
// one fixed profile. Only request.pem travels to the offline signing host.
func PrepareRequest(dir string) error {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	if _, err := enrollment.ParseCSR(der); err != nil {
		return err
	}
	secret, err := privatePEM(key)
	if err != nil {
		return err
	}
	return writeBundle(dir, output{"key.pem", secret}, output{"request.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})})
}

func LoadRequest(path string) (*x509.CertificateRequest, error) {
	b, err := localfile.Read(path, 4096, false)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE REQUEST-----")) {
		return nil, errors.New("expected one CSR PEM")
	}
	block, rest := pem.Decode(b)
	if block == nil || bytes.Count(b, []byte("-----BEGIN")) != 1 || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid CSR PEM")
	}
	return enrollment.ParseCSR(block.Bytes)
}

// Issue requires a directly provisioned, self-signed Ed25519 offline root.
// It cannot sign client identities: those remain registry-bound online issuance.
func Issue(rootCertPath, rootKeyPath, requestPath, profile, dir string, lifetime time.Duration) (Receipt, error) {
	var receipt Receipt
	maximum := ServerLifetime
	if profile == "issuer" {
		maximum = IssuerLifetime
	} else if profile != "server" {
		return receipt, errors.New("offline issuance profile must be server or issuer")
	}
	if lifetime == 0 {
		lifetime = maximum
	}
	if lifetime < time.Hour || lifetime > maximum || lifetime%time.Second != 0 {
		return receipt, errors.New("invalid certificate lifetime for profile")
	}
	certs, err := tlsconfig.LoadCertificates(rootCertPath)
	if err != nil {
		return receipt, err
	}
	if len(certs) != 1 {
		return receipt, errors.New("exactly one offline root certificate required")
	}
	root := certs[0]
	rootKey, err := signing.LoadPrivate(rootKeyPath)
	if err != nil {
		return receipt, err
	}
	rootPublic, ok := root.PublicKey.(ed25519.PublicKey)
	if !ok || !root.IsCA || !root.BasicConstraintsValid || root.MaxPathLen != 1 || root.MaxPathLenZero || root.KeyUsage&x509.KeyUsageCertSign == 0 || len(root.ExtKeyUsage) != 0 || len(root.UnknownExtKeyUsage) != 0 || !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil || !bytes.Equal(rootPublic, rootKey.Public().(ed25519.PublicKey)) {
		return receipt, errors.New("invalid or mismatched offline root profile")
	}
	csr, err := LoadRequest(requestPath)
	if err != nil {
		return receipt, err
	}
	pub := csr.PublicKey.(ed25519.PublicKey)
	if bytes.Equal(pub, rootPublic) {
		return receipt, errors.New("root and issued keys must be distinct")
	}
	now := time.Now()
	if now.Before(root.NotBefore) || !now.Add(time.Hour).Before(root.NotAfter) {
		return receipt, errors.New("offline root is outside its usable validity window")
	}
	n, err := serial()
	if err != nil {
		return receipt, err
	}
	until := now.Add(lifetime)
	if until.After(root.NotAfter) {
		until = root.NotAfter
	}
	start := now.Add(-time.Minute)
	if start.Before(root.NotBefore) {
		start = root.NotBefore
	}
	template := &x509.Certificate{SerialNumber: n, NotBefore: start, NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if profile == "issuer" {
		template.Subject = pkix.Name{CommonName: "Argus-C2 client issuer"}
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.MaxPathLenZero = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		// The Phase 9 public-listener gate has not been entered.
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, pub, rootKey)
	if err != nil {
		return receipt, err
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return receipt, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := issued.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: template.ExtKeyUsage}); err != nil {
		return receipt, err
	}
	receipt = Receipt{1, profile, identity.Fingerprint(root), audit.Digest(csr.Raw), identity.Fingerprint(issued), signing.KeyID(pub), issued.NotBefore.Unix(), issued.NotAfter.Unix()}
	data, err := json.Marshal(receipt)
	if err != nil {
		return receipt, err
	}
	err = writeBundle(dir, output{"certificate.pem", pemCertificate(der)}, output{"receipt.json", data})
	return receipt, err
}
