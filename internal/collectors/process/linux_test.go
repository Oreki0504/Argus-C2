//go:build linux

package process

import (
	"encoding/json"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

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
