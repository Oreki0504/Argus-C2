// Package secretinput reads local passwords without command arguments or echo.
package secretinput

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"golang.org/x/term"
)

func Password(create bool) (string, error) {
	var b []byte
	var err error
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", errors.New("could not read password")
		}
		defer clear(b)
		if create {
			fmt.Fprint(os.Stderr, "Confirm password: ")
			again, e := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			defer clear(again)
			if e != nil || !bytes.Equal(b, again) {
				return "", errors.New("password confirmation failed")
			}
		}
	} else {
		b, err = strictjson.Read(os.Stdin, 258)
		if err != nil {
			return "", errors.New("password input exceeds bounds")
		}
		defer clear(b)
		b = bytes.TrimSuffix(b, []byte{'\n'})
		b = bytes.TrimSuffix(b, []byte{'\r'})
	}
	value := string(b)
	if !adminauth.PasswordInput(value) || (create && !adminauth.NewPassword(value)) {
		return "", errors.New("password must contain at least 15 characters when created, at most 256 UTF-8 bytes, and no control characters")
	}
	return value, nil
}
