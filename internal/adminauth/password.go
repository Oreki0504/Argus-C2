// Package adminauth defines bounded administrator credentials and password KDFs.
package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const Admin = "Admin"
const ReadOnly = "ReadOnly"
const prefix = "$argon2id$v=19$m=65536,t=3,p=4$"

// Fixed, versioned parameters prevent a corrupt hash from selecting arbitrary
// CPU/memory costs. This process admits at most two concurrent KDF operations.
var slots = make(chan struct{}, 2)
var ErrBusy = errors.New("password verification capacity reached")

func Role(s string) bool { return s == Admin || s == ReadOnly }
func Username(s string) bool {
	if len(s) < 3 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func PasswordInput(s string) bool {
	if len(s) < 1 || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func NewPassword(s string) bool { return PasswordInput(s) && utf8.RuneCountInString(s) >= 15 }
func Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, nil
	default:
		return nil, ErrBusy
	}
}
func Hash(password string) (string, error) {
	if !NewPassword(password) {
		return "", errors.New("password must contain at least 15 characters, at most 256 UTF-8 bytes, and no control characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	tag := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return prefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(tag), nil
}
func Parse(encoded string) ([]byte, []byte, error) {
	if !strings.HasPrefix(encoded, prefix) || len(encoded) > 128 {
		return nil, nil, errors.New("unsupported password hash")
	}
	parts := strings.Split(strings.TrimPrefix(encoded, prefix), "$")
	if len(parts) != 2 {
		return nil, nil, errors.New("invalid password hash")
	}
	salt, e1 := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	tag, e2 := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(tag) != 32 {
		return nil, nil, errors.New("invalid password hash")
	}
	return salt, tag, nil
}

// The caller holds Acquire for the complete operation. Unknown users use the
// same KDF parameters and comparison, with an intentionally nonmatching tag.
func Verify(password, encoded string) (bool, error) {
	salt, tag, err := Parse(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(got, tag) == 1, nil
}
func Dummy() string {
	return prefix + base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
}
