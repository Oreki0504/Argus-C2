//go:build linux

package network

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestSocketAddressAndReadBounds(t *testing.T) {
	for _, v := range []struct {
		in, ip string
		port   uint16
	}{{"0100007F:0016", "127.0.0.1", 22}, {"00000000000000000000000001000000:01BB", "::1", 443}} {
		ip, port, e := address(v.in)
		if e != nil || ip != v.ip || port != v.port {
			t.Fatal(ip, port, e)
		}
	}
	out := protocol.Listeners{Available: true, Coverage: "complete", Items: []protocol.Listener{}}
	line := "0: 0100007F:0016 00000000:0000 0A\n"
	if e := read(t.Context(), strings.NewReader("header\n"+strings.Repeat(line, 300)), "tcp", &out); e != nil {
		t.Fatal(e)
	}
	if len(out.Items) != 256 || !out.Truncated {
		t.Fatal("unbounded socket list", len(out.Items))
	}
	b, _ := json.Marshal(out)
	if e := protocol.ValidateListeners(b); e != nil {
		t.Fatal(e)
	}
}

func TestPartialProtocolTablesAreReported(t *testing.T) {
	for _, allMissing := range []bool{false, true} {
		result, e := collect(t.Context(), func(path string) (io.ReadCloser, error) {
			if allMissing || path != "/proc/net/tcp" {
				return nil, os.ErrPermission
			}
			return io.NopCloser(strings.NewReader("header\n0: 0100007F:0016 00000000:0000 0A\n")), nil
		})
		if e != nil {
			t.Fatal(e)
		}
		want := "partial"
		if allMissing {
			want = "unavailable"
		}
		if result.Coverage != want || result.Available == allMissing {
			t.Fatal(result)
		}
		b, _ := json.Marshal(result)
		if e = protocol.ValidateListeners(b); e != nil {
			t.Fatal(e)
		}
	}
	result, e := collect(t.Context(), func(string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("header\n")), nil })
	if e != nil || result.Coverage != "complete" || !result.Available {
		t.Fatal(result, e)
	}
}
func TestByteLimitCannotClaimCompleteCoverage(t *testing.T) {
	out := protocol.Listeners{Available: true, Coverage: "complete", Items: []protocol.Listener{}}
	// Exactly at the byte limit is conservatively partial, even at a line boundary.
	if e := read(t.Context(), strings.NewReader("header\n"+strings.Repeat("0: 0100007F:0016 00000000:0000 01"+strings.Repeat(" ", 480)+"\n", 5000)), "tcp", &out); e != nil {
		t.Fatal(e)
	}
	if out.Coverage != "partial" {
		t.Fatal(out)
	}
}
