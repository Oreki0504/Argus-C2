// Package identity defines canonical node identities and local registrations.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Node struct {
	AgentID         string `json:"agent_id"`
	EnrollmentEpoch string `json:"enrollment_epoch"`
}

func New() Node { return Node{RandomID(), RandomID()} }
func RandomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func Hex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (n Node) Validate() error {
	if !Hex(n.AgentID, 32) || !Hex(n.EnrollmentEpoch, 32) {
		return errors.New("invalid node identity")
	}
	return nil
}
func (n Node) URI() (*url.URL, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return url.Parse("argus://nodes/" + n.AgentID + "/epochs/" + n.EnrollmentEpoch)
}
func Decode(data []byte) (Node, error) {
	var n Node
	if err := strictjson.Decode(data, &n, 4096, "agent_id", "enrollment_epoch"); err != nil {
		return Node{}, err
	}
	return n, n.Validate()
}
func FromCertificate(cert *x509.Certificate) (Node, error) {
	if cert == nil || cert.IsCA || len(cert.URIs) != 1 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 {
		return Node{}, errors.New("certificate is not a probe identity")
	}
	u := cert.URIs[0]
	if u == nil {
		return Node{}, errors.New("missing identity URI")
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 4 || parts[2] != "epochs" {
		return Node{}, errors.New("invalid identity URI")
	}
	n := Node{parts[1], parts[3]}
	expected, err := n.URI()
	if err != nil || u.String() != expected.String() {
		return Node{}, errors.New("noncanonical identity URI")
	}
	return n, nil
}
func Fingerprint(cert *x509.Certificate) string {
	b := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(b[:])
}

type Registration struct {
	AgentID           string `json:"agent_id"`
	EnrollmentEpoch   string `json:"enrollment_epoch"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Enabled           bool   `json:"enabled"`
}

// Authorizer checks the current registration on every connection and request.
type Authorizer interface {
	Authorize(*x509.Certificate) (Node, error)
}

// Registry retains the static development registrations from Phase 2.
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]Registration
}

func NewRegistry(records []Registration) (*Registry, error) {
	if len(records) == 0 || len(records) > 1000 {
		return nil, errors.New("expected 1-1000 registrations")
	}
	r := &Registry{nodes: make(map[string]Registration)}
	for _, record := range records {
		if (Node{record.AgentID, record.EnrollmentEpoch}).Validate() != nil || !Hex(record.CertificateSHA256, 64) {
			return nil, errors.New("invalid registration")
		}
		if _, exists := r.nodes[record.AgentID]; exists {
			return nil, errors.New("duplicate agent registration")
		}
		r.nodes[record.AgentID] = record
	}
	return r, nil
}
func (r *Registry) Authorize(cert *x509.Certificate) (Node, error) {
	n, err := FromCertificate(cert)
	if err != nil {
		return Node{}, err
	}
	// A keep-alive connection may outlive the certificate's validity window.
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return Node{}, errors.New("node certificate is outside its validity window")
	}
	if r == nil {
		return Node{}, errors.New("no registry")
	}
	r.mu.RLock()
	record, ok := r.nodes[n.AgentID]
	r.mu.RUnlock()
	if !ok || !record.Enabled || record.EnrollmentEpoch != n.EnrollmentEpoch || record.CertificateSHA256 != Fingerprint(cert) {
		return Node{}, errors.New("node identity is not authorized")
	}
	return n, nil
}
func (r *Registry) Disable(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if record, ok := r.nodes[agentID]; ok {
		record.Enabled = false
		r.nodes[agentID] = record
	}
}
