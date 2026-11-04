package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, e := localfile.Read(path, 16384, true)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid agent key")
	}
	v, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	key, ok := v.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("expected P-256 private key")
	}
	return key, nil
}
func atomicWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func verifyCertificate(certificate string, key *ecdsa.PrivateKey, ca, id string) (*x509.Certificate, error) {
	keyPEM, e := enrollment.KeyPEM(key)
	if e != nil {
		return nil, e
	}
	pair, e := tls.X509KeyPair([]byte(certificate), keyPEM)
	if e != nil {
		return nil, e
	}
	cert, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	actual, e := identity.FromCertificate(cert)
	if e != nil || actual != id {
		return nil, errors.New("certificate identity mismatch")
	}
	roots, e := transport.Roots(ca)
	if e != nil {
		return nil, e
	}
	_, e = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return cert, e
}
func Enroll(ctx context.Context, server, ca, dir, token, hostname string) error {
	if e := transport.ValidateURL(server); e != nil {
		return e
	}
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !st.IsDir() || runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return errors.New("agent directory must be private")
	}
	if _, e = os.Stat(filepath.Join(dir, "agent.pem")); e == nil {
		return errors.New("agent already enrolled")
	} else if !os.IsNotExist(e) {
		return e
	}
	keyPath := filepath.Join(dir, "agent-key.pem")
	key, e := loadKey(keyPath)
	if os.IsNotExist(e) {
		key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		b, e := enrollment.KeyPEM(key)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		if e = syncDir(dir); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	csr, e := enrollment.CSR(key)
	if e != nil {
		return e
	}
	client, e := transport.Client(ca, "", "")
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	b, e := transport.Request(ctx, client, server, "", "POST", "/v1/enroll", struct {
		Token    string `json:"token"`
		Hostname string `json:"hostname"`
		CSR      []byte `json:"csr"`
	}{token, hostname, csr})
	if e != nil {
		return e
	}
	var response struct {
		NodeID      string `json:"node_id"`
		Certificate string `json:"certificate"`
	}
	if e = json.Unmarshal(b, &response); e != nil {
		return e
	}
	if _, e = verifyCertificate(response.Certificate, key, ca, response.NodeID); e != nil {
		return e
	}
	// Initialize durable identity before exposing credentials as enrolled.
	state, e := OpenState(dir, response.NodeID, true)
	if e != nil {
		return e
	}
	if e = state.Close(); e != nil {
		return e
	}
	return atomicWrite(filepath.Join(dir, "agent.pem"), []byte(response.Certificate))
}
