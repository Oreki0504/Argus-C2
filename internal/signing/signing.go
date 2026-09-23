// Package signing signs and verifies the fixed Phase 1 task envelope.
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const domain = "argus-c2/task/v1\x00"

type envelope struct {
	Payload   string `json:"payload_b64"`
	Signature string `json:"signature_b64"`
}

func message(payload []byte) []byte { return append([]byte(domain), payload...) }
func Sign(payload []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	if _, err := protocol.DecodeTask(payload); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, message(payload))
	return json.Marshal(envelope{base64.RawURLEncoding.EncodeToString(payload), base64.RawURLEncoding.EncodeToString(sig)})
}

// Verify verifies original bytes before interpreting the payload. Success does
// not authorize execution or provide replay protection.
func Verify(data []byte, key ed25519.PublicKey) (protocol.Task, error) {
	if len(key) != ed25519.PublicKeySize {
		return protocol.Task{}, errors.New("invalid verification key")
	}
	var e envelope
	if err := strictjson.Decode(data, &e, protocol.MaxEnvelopeBytes, "payload_b64", "signature_b64"); err != nil {
		return protocol.Task{}, err
	}
	payload, err := decode(e.Payload, protocol.MaxPayloadBytes)
	if err != nil {
		return protocol.Task{}, err
	}
	sig, err := decode(e.Signature, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return protocol.Task{}, errors.New("invalid signature encoding")
	}
	if !ed25519.Verify(key, message(payload), sig) {
		return protocol.Task{}, errors.New("invalid signature")
	}
	return protocol.DecodeTask(payload)
}
func decode(s string, limit int) ([]byte, error) {
	if len(s) > base64.RawURLEncoding.EncodedLen(limit) {
		return nil, errors.New("encoded value too large")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > limit || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errors.New("noncanonical base64url")
	}
	return b, nil
}
