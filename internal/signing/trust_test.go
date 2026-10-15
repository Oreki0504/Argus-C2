package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func trustFixture(t testing.TB) (TrustSet, ed25519.PrivateKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	oldPub, old, _ := ed25519.GenerateKey(rand.Reader)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(2000000000, 0)
	s, err := Stage(oldPub, nil, pub, now, now.Add(time.Hour).Unix(), now.Add(30*24*time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	return s, old, key, now
}

func TestTrustedEnvelopeBindsBothIDsAndOriginalBytes(t *testing.T) {
	s, old, key, now := trustFixture(t)
	wire, err := SignTrusted(signingPayload(), key, s, now)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, id, err := VerifyTrusted(wire, s, now)
	if err != nil || !bytes.Equal(payload, signingPayload()) || id != KeyID(key.Public().(ed25519.PublicKey)) {
		t.Fatal("trusted signature", err)
	}
	var original envelopeV2
	json.Unmarshal(wire, &original)
	for name, mutate := range map[string]func(*envelopeV2){
		"key ID":      func(e *envelopeV2) { e.KeyID = KeyID(old.Public().(ed25519.PublicKey)) },
		"unknown key": func(e *envelopeV2) { e.KeyID = strings.Repeat("f", 64) },
		"trust ID":    func(e *envelopeV2) { e.TrustID = strings.Repeat("b", 32) },
		"version":     func(e *envelopeV2) { e.Version = 1 },
		"payload bytes": func(e *envelopeV2) {
			e.Payload = base64.RawURLEncoding.EncodeToString(append([]byte(" "), signingPayload()...))
		},
		"signature domain": func(e *envelopeV2) {
			e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message(signingPayload())))
		},
		"encoding": func(e *envelopeV2) { e.Payload += "=" },
	} {
		t.Run(name, func(t *testing.T) {
			e := original
			mutate(&e)
			b, _ := json.Marshal(e)
			if _, _, _, err := VerifyTrusted(b, s, now); err == nil {
				t.Fatal("accepted mutation")
			}
		})
	}
	// Even when the same public key is trusted elsewhere, changing the trust ID
	// cannot transfer a signed envelope to that trust domain.
	other := s
	other.ID = strings.Repeat("b", 32)
	e := original
	e.TrustID = other.ID
	changed, _ := json.Marshal(e)
	if _, _, _, err := VerifyTrusted(changed, other, now); err == nil {
		t.Fatal("cross trust-set signature")
	}
	legacy, _ := Sign(signingPayload(), old)
	if _, _, _, err := VerifyTrusted(legacy, s, now); err != nil {
		t.Fatal("legacy overlap", err)
	}
	downgrade, _ := Sign(signingPayload(), key)
	if _, _, _, err := VerifyTrusted(downgrade, s, now); err == nil {
		t.Fatal("new key accepted as legacy")
	}
	if _, err := Verify(wire, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("legacy reader accepted v2")
	}
	for _, b := range [][]byte{
		append(wire, []byte(`{}`)...),
		bytes.Replace(wire, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
		bytes.Replace(wire, []byte(`"version":2`), []byte(`"Version":2`), 1),
		bytes.Replace(wire, []byte(`"version":2`), []byte(`"version":2,"public_key_b64":"AA"`), 1),
	} {
		if _, _, _, err := VerifyTrusted(b, s, now); err == nil {
			t.Fatal("accepted ambiguous or supplied-key envelope")
		}
	}
}

func TestKeyWindowsAndRetirement(t *testing.T) {
	s, old, key, now := trustFixture(t)
	wire, _ := SignTrusted(signingPayload(), old, s, now)
	for _, at := range []time.Time{now.Add(-time.Hour), now.Add(time.Hour)} {
		if _, _, _, err := VerifyTrusted(wire, s, at); err == nil {
			t.Fatal("accepted outside key validity", at)
		}
	}
	short := s
	short.Keys = append([]TrustKey{}, s.Keys...)
	short.Keys[1].NotAfter = now.Unix() + 30
	if _, err := SignTrusted(signingPayload(), key, short, now); err == nil {
		t.Fatal("task outlives signer")
	}
	next, err := Retire(s, KeyID(old.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := VerifyTrusted(wire, next, now); err == nil {
		t.Fatal("retired key remains trusted")
	}
	newWire, _ := SignTrusted(signingPayload(), key, next, now)
	if _, _, _, err := VerifyTrusted(newWire, next, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(nil, &next, old.Public().(ed25519.PublicKey), now, now.Add(time.Hour).Unix(), now.Add(48*time.Hour).Unix()); err == nil {
		t.Fatal("revived retired key")
	}
	if err := CheckTransition(&next, "", s); err == nil {
		t.Fatal("rollback accepted")
	}
	extended := next
	extended.Keys = append([]TrustKey{}, next.Keys...)
	extended.Keys[0].NotAfter++
	if err := CheckTransition(&s, "", extended); err == nil {
		t.Fatal("key lifetime extended")
	}
}

func TestStrictTrustDocuments(t *testing.T) {
	s, _, _, _ := trustFixture(t)
	b, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(b, []byte(`"allow_legacy"`), []byte(`"Allow_Legacy"`), 1),
		bytes.Replace(b, []byte(`"generation":1`), []byte(`"generation":1,"generation":1`), 1),
		bytes.Replace(b, []byte(`"retired_key_ids":[]`), []byte(`"retired_key_ids":null`), 1),
		bytes.Replace(b, []byte(`"keys":[`), []byte(`"url":"https://example.invalid/key","keys":[`), 1),
		append(b, []byte(`{}`)...),
	} {
		if _, err := DecodeTrust(bad); err == nil {
			t.Fatal("ambiguous trust document accepted")
		}
	}
	s.Keys[1] = s.Keys[0]
	if s.Validate() == nil {
		t.Fatal("duplicate key")
	}
}

func FuzzTrustSet(f *testing.F) {
	s, _, _, _ := trustFixture(f)
	b, _ := s.Canonical()
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeTrust(b)
		if err == nil {
			c, err := s.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeTrust(c); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzVerifyTrusted(f *testing.F) {
	s, old, key, now := trustFixture(f)
	b, _ := SignTrusted(signingPayload(), key, s, now)
	legacy, _ := Sign(signingPayload(), old)
	f.Add(b)
	f.Add(legacy)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		task, _, id, err := VerifyTrusted(b, s, now)
		if err == nil && (task.Validate() != nil || s.CheckTask(task, id, now) != nil) {
			t.Fatal("invalid trusted task")
		}
	})
}
