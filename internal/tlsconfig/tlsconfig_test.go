package tlsconfig_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func TestRejectInvalidLocalCredentials(t *testing.T) {
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "pki")
	if err := b.WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	files := tlsconfig.Files{Certificate: filepath.Join(dir, "probe-cert.pem"), PrivateKey: filepath.Join(dir, "probe-key.pem"), CA: filepath.Join(dir, "ca.pem")}
	if _, err := tlsconfig.Client(files, identity.New(), "localhost"); err == nil {
		t.Fatal("accepted mismatched local identity")
	}
	if _, err := tlsconfig.Client(files, b.Node, ""); err == nil {
		t.Fatal("accepted empty server name")
	}
	wrong := files
	wrong.PrivateKey = filepath.Join(dir, "server-key.pem")
	if _, err := tlsconfig.Client(wrong, b.Node, "localhost"); err == nil {
		t.Fatal("accepted mismatched private key")
	}
	wrong = files
	wrong.Certificate = filepath.Join(dir, "server-cert.pem")
	wrong.PrivateKey = filepath.Join(dir, "server-key.pem")
	if _, err := tlsconfig.Client(wrong, b.Node, "localhost"); err == nil {
		t.Fatal("accepted server certificate as node")
	}
	for _, contents := range [][]byte{nil, []byte("not PEM"), b.Probe.PEM, append(append([]byte{}, b.CA.PEM...), []byte("garbage")...)} {
		if err := os.WriteFile(files.CA, contents, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := tlsconfig.Client(files, b.Node, "localhost"); err == nil {
			t.Fatal("accepted invalid CA bundle")
		}
	}
}
