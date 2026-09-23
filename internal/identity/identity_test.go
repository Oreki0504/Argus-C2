package identity_test

import (
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
)

func TestCertificateIdentity(t *testing.T) {
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	n, err := identity.FromCertificate(b.Probe.Leaf)
	if err != nil || n != b.Node {
		t.Fatal("identity round trip failed", err)
	}
	for _, uri := range []string{
		"https://nodes/" + n.AgentID + "/epochs/" + n.EnrollmentEpoch,
		"argus://nodes/" + n.AgentID + "/epochs/" + n.EnrollmentEpoch + "?admin=true",
		"argus://nodes/" + n.AgentID + "/epochs/" + n.EnrollmentEpoch + "#fragment",
		"argus://user@nodes/" + n.AgentID + "/epochs/" + n.EnrollmentEpoch,
		"argus://nodes/" + n.AgentID + "/epochs/" + n.EnrollmentEpoch + "/",
	} {
		cert := *b.Probe.Leaf
		u, _ := url.Parse(uri)
		cert.URIs = []*url.URL{u}
		if _, err := identity.FromCertificate(&cert); err == nil {
			t.Fatalf("accepted noncanonical URI %s", uri)
		}
	}
	cert := *b.Probe.Leaf
	cert.URIs = append(cert.URIs, cert.URIs[0])
	if _, err := identity.FromCertificate(&cert); err == nil {
		t.Fatal("accepted multiple URIs")
	}
	cert = *b.Probe.Leaf
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	if _, err := identity.FromCertificate(&cert); err == nil {
		t.Fatal("accepted broad certificate purpose")
	}
}
func TestRegistryBinding(t *testing.T) {
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	record := b.Registration()
	r, err := identity.NewRegistry([]identity.Registration{record})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authorize(b.Probe.Leaf); err != nil {
		t.Fatal(err)
	}
	stale := *b.Probe.Leaf
	stale.NotAfter = time.Now().Add(-time.Second)
	if _, err := r.Authorize(&stale); err == nil {
		t.Fatal("accepted a registered identity after certificate expiration")
	}
	template, _ := devpki.ClientTemplate(b.Node)
	replacement, err := b.CA.Issue(template)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authorize(replacement.Leaf); err == nil {
		t.Fatal("accepted unregistered replacement certificate")
	}
	r.Disable(b.Node.AgentID)
	if _, err := r.Authorize(b.Probe.Leaf); err == nil {
		t.Fatal("accepted disabled node")
	}
	if _, err := identity.NewRegistry([]identity.Registration{record, record}); err == nil {
		t.Fatal("accepted duplicate identity")
	}
	if _, err := identity.NewRegistry(nil); err == nil {
		t.Fatal("accepted empty registry")
	}
}
