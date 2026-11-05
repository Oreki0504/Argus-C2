//go:build linux

package network

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("injected read failure") }

func TestReadFailureKeepsEarlierObservations(t *testing.T) {
	line := "header\n0: 0100007F:0016 00000000:0000 0A\n"
	for _, oversize := range []bool{false, true} {
		out, err := collect(t.Context(), func(path string) (io.ReadCloser, error) {
			if path != "/proc/net/tcp" {
				return nil, os.ErrPermission
			}
			var tail io.Reader = failedReader{}
			if oversize {
				tail = strings.NewReader(strings.Repeat("x", 9000))
			}
			return io.NopCloser(io.MultiReader(strings.NewReader(line), tail)), nil
		})
		if err != nil || !out.Available || out.Coverage != "partial" || len(out.Items) != 1 || out.Truncated != oversize {
			t.Fatal(out, err)
		}
		b, _ := json.Marshal(out)
		if err = protocol.ValidateListeners(b); err != nil {
			t.Fatal(err)
		}
	}
	out, err := collect(t.Context(), func(string) (io.ReadCloser, error) { return io.NopCloser(failedReader{}), nil })
	if err != nil || out.Available || out.Coverage != "unavailable" {
		t.Fatal(out, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = collect(ctx, func(string) (io.ReadCloser, error) { t.Fatal("opened after cancel"); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMalformedSocketRowsArePartial(t *testing.T) {
	out := protocol.Listeners{Coverage: "complete", Items: []protocol.Listener{}}
	data := "header\n0: 0100007F:0016 00000000:0000 ZZ\n0: 00000000000000000000000001000000:0016 00000000:0000 0A\n0: 0100007F:0016 00000000:0000 0A\n"
	if err := read(t.Context(), strings.NewReader(data), "tcp", &out); err != nil || out.Coverage != "partial" || len(out.Items) != 1 {
		t.Fatal(out, err)
	}
}

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
