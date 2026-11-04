// Package auth authenticates named administrators with high-entropy API tokens.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type User struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	TokenSHA256 string `json:"token_sha256"`
}
type Config struct {
	Users []User `json:"users"`
}

func Digest(token string) string { h := sha256.Sum256([]byte(token)); return hex.EncodeToString(h[:]) }
func Load(path string) (Config, error) {
	var c Config
	b, e := localfile.Read(path, 32768, true)
	if e != nil {
		return c, e
	}
	if e = strictjson.Decode(b, &c, 32768, "users"); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if len(c.Users) < 1 || len(c.Users) > 100 {
		return errors.New("expected 1-100 administrator accounts")
	}
	names, hashes := map[string]bool{}, map[string]bool{}
	for _, u := range c.Users {
		if !identity.Valid(u.Name) || (u.Role != "Admin" && u.Role != "ReadOnly") || !identity.Hex(u.TokenSHA256, 64) || names[u.Name] || hashes[u.TokenSHA256] {
			return errors.New("invalid or duplicate administrator")
		}
		names[u.Name] = true
		hashes[u.TokenSHA256] = true
	}
	return nil
}
func (c Config) Authenticate(token string) (User, error) {
	if len(token) < 40 || len(token) > 256 {
		return User{}, errors.New("unauthorized")
	}
	want := Digest(token)
	for _, u := range c.Users {
		if subtle.ConstantTimeCompare([]byte(want), []byte(u.TokenSHA256)) == 1 {
			return u, nil
		}
	}
	return User{}, errors.New("unauthorized")
}
func NewUser(name, role string) (User, string, error) {
	token := identity.RandomID() + identity.RandomID()
	u := User{name, role, Digest(token)}
	return u, token, (Config{Users: []User{u}}).Validate()
}
