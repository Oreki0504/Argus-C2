package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func signingPayload() []byte {
	data, _ := json.Marshal(protocol.Task{Version: 1, RequestID: strings.Repeat("1", 32), AgentID: strings.Repeat("2", 32), EnrollmentEpoch: strings.Repeat("3", 32), CreatedAt: 2000000000, ExpiresAt: 2000000060, Type: protocol.SystemInfo, TaskVersion: 1, Params: json.RawMessage(`{}`), ActorID: "admin", PolicyDigest: strings.Repeat("a", 64)})
	return data
}
func TestSignatureVerification(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	payload := signingPayload()
	wire, err := Sign(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(wire, pub); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(wire, other); err == nil {
		t.Fatal("accepted wrong signing key")
	}
	var original envelope
	_ = json.Unmarshal(wire, &original)
	for name, mutate := range map[string]func(*envelope){
		"changed payload": func(e *envelope) { e.Payload = base64.RawURLEncoding.EncodeToString(append([]byte(" "), payload...)) },
		"missing domain":  func(e *envelope) { e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload)) },
		"padded payload":  func(e *envelope) { e.Payload += "=" },
		"newline":         func(e *envelope) { e.Payload += "\n" },
		"oversized":       func(e *envelope) { e.Payload = strings.Repeat("A", 20000) },
		"short signature": func(e *envelope) { e.Signature = "AA" },
	} {
		t.Run(name, func(t *testing.T) {
			e := original
			mutate(&e)
			altered, _ := json.Marshal(e)
			if _, err := Verify(altered, pub); err == nil {
				t.Fatal("accepted invalid envelope")
			}
		})
	}
	if _, err := Sign(payload, nil); err == nil {
		t.Fatal("accepted missing private key")
	}
	if _, err := Verify(wire, nil); err == nil {
		t.Fatal("accepted missing public key")
	}
	// Valid cryptography must not allow an unknown task shape through decoding.
	bad := []byte(strings.Replace(string(payload), "system.info", "shell", 1))
	signedBad, _ := json.Marshal(envelope{base64.RawURLEncoding.EncodeToString(bad), base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message(bad)))})
	if _, err := Verify(signedBad, pub); err == nil {
		t.Fatal("accepted signed unsupported task")
	}
}
func FuzzVerify(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	wire, _ := Sign(signingPayload(), key)
	f.Add(wire)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		task, err := Verify(b, pub)
		if err == nil && task.Validate() != nil {
			t.Fatal("accepted invalid task")
		}
	})
}
