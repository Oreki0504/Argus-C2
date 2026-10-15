package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxTrustBytes = 16 * 1024
const MaxRetiredKeys = 64
const MaxSignerOverlap = 24 * time.Hour

// TrustSet is installed through local administration, never from a task or TLS
// response. Key IDs are SHA-256 of raw Ed25519 public keys, not names or URLs.
type TrustSet struct {
	Version    int        `json:"version"`
	ID         string     `json:"trust_set_id"`
	Generation int        `json:"generation"`
	Keys       []TrustKey `json:"keys"`
	Retired    []string   `json:"retired_key_ids"`
}

type TrustKey struct {
	ID        string `json:"key_id"`
	Public    string `json:"public_key_b64"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	Legacy    bool   `json:"allow_legacy"`
}

func KeyID(key ed25519.PublicKey) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])
}

func NewTrustKey(key ed25519.PublicKey, start, end int64, legacy bool) TrustKey {
	return TrustKey{KeyID(key), base64.RawURLEncoding.EncodeToString(key), start, end, legacy}
}

func (k TrustKey) PublicKey() (ed25519.PublicKey, error) {
	b, err := decode(k.Public, ed25519.PublicKeySize)
	if err != nil || len(b) != ed25519.PublicKeySize || KeyID(b) != k.ID {
		return nil, errors.New("invalid trust key or key ID")
	}
	return ed25519.PublicKey(b), nil
}

func (s TrustSet) Validate() error {
	if s.Version != 1 || !identity.Hex(s.ID, 32) || s.Generation < 1 || s.Generation > 2*MaxRetiredKeys+1 || len(s.Keys) < 1 || len(s.Keys) > 2 || s.Retired == nil || len(s.Retired) > MaxRetiredKeys {
		return errors.New("invalid signer trust set")
	}
	seen := map[string]bool{}
	for _, id := range s.Retired {
		if !identity.Hex(id, 64) || seen[id] {
			return errors.New("invalid retired key history")
		}
		seen[id] = true
	}
	legacy := 0
	for _, k := range s.Keys {
		if _, err := k.PublicKey(); err != nil {
			return err
		}
		if seen[k.ID] || k.NotBefore <= 0 || k.NotAfter <= k.NotBefore {
			return errors.New("duplicate, retired, or invalid key window")
		}
		seen[k.ID] = true
		if k.Legacy {
			legacy++
		}
	}
	if legacy > 1 {
		return errors.New("only one legacy key is allowed")
	}
	if len(s.Keys) == 2 {
		start := max(s.Keys[0].NotBefore, s.Keys[1].NotBefore)
		end := min(s.Keys[0].NotAfter, s.Keys[1].NotAfter)
		if end <= start || end-start > int64(MaxSignerOverlap/time.Second) {
			return errors.New("signer overlap must be positive and at most 24 hours")
		}
	}
	return nil
}

func DecodeTrust(data []byte) (TrustSet, error) {
	var s TrustSet
	if err := strictjson.Decode(data, &s, MaxTrustBytes, "version", "trust_set_id", "generation", "keys", "retired_key_ids"); err != nil {
		return s, err
	}
	// Strict top-level validation alone does not reject case-folded nested names.
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return s, err
	}
	for _, b := range raw.Keys {
		var k TrustKey
		if err := strictjson.Decode(b, &k, 1024, "key_id", "public_key_b64", "not_before", "not_after", "allow_legacy"); err != nil {
			return s, err
		}
	}
	return s, s.Validate()
}

func (s TrustSet) Canonical() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	s.Keys = slices.Clone(s.Keys)
	s.Retired = append([]string{}, s.Retired...)
	slices.SortFunc(s.Keys, func(a, b TrustKey) int { return bytes.Compare([]byte(a.ID), []byte(b.ID)) })
	slices.Sort(s.Retired)
	return json.Marshal(s)
}

func LoadTrust(path string) (TrustSet, error) {
	b, err := localfile.Read(path, MaxTrustBytes, false)
	if err != nil {
		return TrustSet{}, err
	}
	return DecodeTrust(b)
}

// LoadVerification accepts the original PEM file or an explicitly migrated
// trust-set JSON at the same root-controlled configuration path.
func LoadVerification(path string) (ed25519.PublicKey, *TrustSet, error) {
	b, err := localfile.Read(path, MaxTrustBytes, false)
	if err != nil {
		return nil, nil, err
	}
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("-----BEGIN PUBLIC KEY-----")) {
		k, err := LoadPublic(path)
		return k, nil, err
	}
	s, err := DecodeTrust(b)
	return nil, &s, err
}

func (s TrustSet) Key(id string) (TrustKey, error) {
	for _, k := range s.Keys {
		if k.ID == id {
			return k, nil
		}
	}
	return TrustKey{}, errors.New("task key is not locally trusted")
}

func (s TrustSet) CheckTask(t protocol.Task, id string, now time.Time) error {
	k, err := s.Key(id)
	if err != nil {
		return err
	}
	if now.Unix() < k.NotBefore || now.Unix() >= k.NotAfter || t.CreatedAt < k.NotBefore || t.ExpiresAt > k.NotAfter {
		return errors.New("task lies outside the local signing-key window")
	}
	return nil
}

// CheckTransition prevents rollback, silent trust replacement, revival of a
// retired key, and extension of an existing key's authority. Each step adds or
// removes one key; a stable identifier survives the entire local lifecycle.
func CheckTransition(previous *TrustSet, legacyID string, next TrustSet) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if previous == nil {
		k, err := next.Key(legacyID)
		if err != nil || !k.Legacy || next.Generation != 1 || len(next.Retired) != 0 || len(next.Keys) != 2 {
			return errors.New("initial migration must retain the pinned legacy key and add one key")
		}
		return nil
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	if next.ID != previous.ID || next.Generation != previous.Generation+1 || len(next.Keys) == len(previous.Keys) {
		return errors.New("trust ID, generation, or transition mismatch")
	}
	expectedRetired := append([]string{}, previous.Retired...)
	shared := 0
	for _, old := range previous.Keys {
		k, err := next.Key(old.ID)
		if err != nil {
			expectedRetired = append(expectedRetired, old.ID)
			continue
		}
		shared++
		if k.Public != old.Public || k.NotBefore != old.NotBefore || k.NotAfter > old.NotAfter || k.Legacy != old.Legacy {
			return errors.New("existing key authority must not be extended or rebound")
		}
	}
	for _, k := range next.Keys {
		if _, err := previous.Key(k.ID); err != nil && k.Legacy {
			return errors.New("new keys cannot authorize legacy envelopes")
		}
	}
	slices.Sort(expectedRetired)
	actual := slices.Clone(next.Retired)
	slices.Sort(actual)
	if shared != 1 || !slices.Equal(expectedRetired, actual) {
		return errors.New("trust continuity or retired history mismatch")
	}
	return nil
}

// Stage adds a new key and shortens the previous key to a bounded overlap.
func Stage(legacy ed25519.PublicKey, previous *TrustSet, nextKey ed25519.PublicKey, now time.Time, retireAt, validUntil int64) (TrustSet, error) {
	if len(nextKey) != ed25519.PublicKeySize || retireAt <= now.Unix()+protocol.MaxLifetime || retireAt-now.Unix() > int64(MaxSignerOverlap/time.Second) || validUntil <= retireAt {
		return TrustSet{}, errors.New("require a new key, overlap over 5 minutes and at most 24 hours, and later new-key expiry")
	}
	var s TrustSet
	if previous == nil {
		if len(legacy) != ed25519.PublicKeySize {
			return s, errors.New("legacy public key required")
		}
		s = TrustSet{1, identity.RandomID(), 1, []TrustKey{NewTrustKey(legacy, now.Unix()-protocol.MaxLifetime-protocol.MaxClockSkew, retireAt, true)}, []string{}}
	} else {
		if err := previous.Validate(); err != nil {
			return s, err
		}
		if len(previous.Keys) != 1 {
			return s, errors.New("retire the previous overlap key before staging another")
		}
		if len(previous.Retired) >= MaxRetiredKeys || previous.Keys[0].NotAfter <= now.Unix()+protocol.MaxLifetime {
			return s, errors.New("retirement history is full or the current key expires too soon for staging")
		}
		s = *previous
		s.Generation++
		s.Keys = slices.Clone(previous.Keys)
		s.Keys[0].NotAfter = min(s.Keys[0].NotAfter, retireAt)
	}
	s.Keys = append(s.Keys, NewTrustKey(nextKey, now.Unix(), validUntil, false))
	return s, CheckTransition(previous, KeyID(legacy), s)
}

func Retire(previous TrustSet, id string) (TrustSet, error) {
	s := previous
	s.Generation++
	s.Keys = nil
	s.Retired = append(append([]string{}, previous.Retired...), id)
	for _, k := range previous.Keys {
		if k.ID != id {
			s.Keys = append(s.Keys, k)
		}
	}
	return s, CheckTransition(&previous, "", s)
}
