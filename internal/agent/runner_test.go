package agent

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/policy"
)

func TestExpiredCertificateBlocksStepBeforeNetwork(t *testing.T) {
	s, err := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// A nil Client makes any accidental network/renewal attempt fail this test.
	r := &Runner{Engine: &Engine{State: s, Policy: policy.Default()}, cert: &x509.Certificate{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(-time.Second)}}
	if err = r.Step(t.Context()); err == nil {
		t.Fatal("expired identity admitted")
	}
}
