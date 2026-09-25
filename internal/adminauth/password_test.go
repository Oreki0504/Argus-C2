package adminauth

import (
	"errors"
	"strings"
	"testing"
)

func TestVersionedPasswordHashesAndBounds(t *testing.T) {
	password := "correct horse battery staple"
	first, err := Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Hash(password)
	if err != nil || first == second {
		t.Fatal("salt was not independent", err)
	}
	if ok, err := Verify(password, first); err != nil || !ok {
		t.Fatal("valid password rejected", err)
	}
	if ok, err := Verify("wrong", first); err != nil || ok {
		t.Fatal("wrong password accepted", err)
	}
	for _, bad := range []string{strings.Replace(first, "m=65536", "m=4294967295", 1), strings.Replace(first, "v=19", "v=16", 1), first + "$extra", "$argon2id$v=19$m=65536,t=3,p=4$AA$AA"} {
		if _, _, err := Parse(bad); err == nil {
			t.Fatal("unbounded/unknown hash accepted")
		}
	}
	for _, bad := range []string{"short", strings.Repeat("x", 257), "password\npassword", "\x00long-password-here"} {
		if _, err := Hash(bad); err == nil {
			t.Fatal("bad password accepted")
		}
	}
	a, err := Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	b, err := Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer b()
	if release, err := Acquire(t.Context()); !errors.Is(err, ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("KDF concurrency unbounded")
	}
}
func FuzzPasswordHashParsing(f *testing.F) {
	f.Add(Dummy())
	f.Add("$argon2id$v=19$m=999999999,t=3,p=4$AAAA$AAAA")
	f.Fuzz(func(t *testing.T, s string) {
		salt, tag, err := Parse(s)
		if err == nil && (len(salt) != 16 || len(tag) != 32 || !strings.HasPrefix(s, prefix)) {
			t.Fatal("invalid accepted hash")
		}
	})
}
