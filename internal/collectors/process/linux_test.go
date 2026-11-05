//go:build linux

package process

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestPartialProcessReadPreservesGoodMetadata(t *testing.T) {
	good := []byte("Name:\tsshd\nState:\tS (sleeping)\nUid:\t1000 1000 1000 1000\n")
	for _, endErr := range []error{io.EOF, errors.New("directory I/O error")} {
		out, err := collect(t.Context(), func(int) ([]string, error) { return []string{"1", "2", "3", "self"}, endErr }, func(name string) ([]byte, error) {
			switch name {
			case "1":
				return good, nil
			case "2":
				return nil, os.ErrNotExist
			default:
				return []byte("Name: bad\nState: ?\nUid: 1\n"), nil
			}
		})
		if err != nil || !out.Available || !out.Truncated || len(out.Items) != 1 {
			t.Fatal(out, err)
		}
		b, _ := json.Marshal(out)
		if err = protocol.ValidateProcesses(b); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := collect(ctx, func(int) ([]string, error) { t.Fatal("read after cancel"); return nil, io.EOF }, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, state := range []string{"?", "SS", ""} {
		if _, ok := parse(1, "Name: x\nState: "+state+"\nUid: 0\n"); ok {
			t.Fatal("invalid state", state)
		}
	}
}

func TestProcessMetadataContainsNoArguments(t *testing.T) {
	p, ok := parse(123, "Name:\tsshd\nState:\tS (sleeping)\nUid:\t1000 1000 1000 1000\nSecret:\tpassword\n")
	if !ok || p.PID != 123 || p.Name != "sshd" || p.UID != 1000 {
		t.Fatal(p)
	}
	if _, ok = parse(1, "Name:\tbad\nState:\tS\n"); ok {
		t.Fatal("missing UID accepted")
	}
	v, e := Collect(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(v)
	if e = protocol.ValidateProcesses(b); e != nil {
		t.Fatal(e)
	}
}
