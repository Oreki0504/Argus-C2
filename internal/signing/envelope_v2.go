package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type envelopeV2 struct {
	Version   int    `json:"version"`
	TrustID   string `json:"trust_set_id"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload_b64"`
	Signature string `json:"signature_b64"`
}

func messageV2(trust, key string, payload []byte) []byte {
	return append([]byte("argus-c2/task/v2\x00"+trust+"\x00"+key+"\x00"), payload...)
}

func SignTrusted(payload []byte, key ed25519.PrivateKey, trust TrustSet, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	if err := trust.Validate(); err != nil {
		return nil, err
	}
	t, err := protocol.DecodeTask(payload)
	if err != nil {
		return nil, err
	}
	id := KeyID(key.Public().(ed25519.PublicKey))
	if err := trust.CheckTask(t, id, now); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, messageV2(trust.ID, id, payload))
	return json.Marshal(envelopeV2{2, trust.ID, id, base64.RawURLEncoding.EncodeToString(payload), base64.RawURLEncoding.EncodeToString(sig)})
}

// VerifyTrusted verifies the original bytes, including both lookup IDs, before
// interpreting task contents. It never fetches a key or installs supplied trust.
func VerifyTrusted(data []byte, trust TrustSet, now time.Time) (protocol.Task, []byte, string, error) {
	bad := func(err error) (protocol.Task, []byte, string, error) { return protocol.Task{}, nil, "", err }
	if err := trust.Validate(); err != nil {
		return bad(err)
	}
	var e envelopeV2
	if err := strictjson.Decode(data, &e, protocol.MaxEnvelopeBytes, "version", "trust_set_id", "key_id", "payload_b64", "signature_b64"); err != nil {
		// The legacy decoder still requires exactly its two original fields.
		for _, k := range trust.Keys {
			if !k.Legacy {
				continue
			}
			pub, err := k.PublicKey()
			if err != nil {
				return bad(err)
			}
			t, payload, err := VerifyPayload(data, pub)
			if err != nil {
				return bad(err)
			}
			if err := trust.CheckTask(t, k.ID, now); err != nil {
				return bad(err)
			}
			return t, payload, k.ID, nil
		}
		return bad(err)
	}
	if e.Version != 2 || e.TrustID != trust.ID {
		return bad(errors.New("unsupported envelope version or trust ID"))
	}
	k, err := trust.Key(e.KeyID)
	if err != nil {
		return bad(err)
	}
	pub, err := k.PublicKey()
	if err != nil {
		return bad(err)
	}
	payload, err := decode(e.Payload, protocol.MaxPayloadBytes)
	if err != nil {
		return bad(err)
	}
	sig, err := decode(e.Signature, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, messageV2(e.TrustID, e.KeyID, payload), sig) {
		return bad(errors.New("invalid task signature"))
	}
	t, err := protocol.DecodeTask(payload)
	if err != nil {
		return bad(err)
	}
	if err := trust.CheckTask(t, e.KeyID, now); err != nil {
		return bad(err)
	}
	return t, payload, e.KeyID, nil
}
