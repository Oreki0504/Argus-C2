//go:build linux

// Package network reads only local procfs socket tables; it sends no probes.
package network

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func address(s string) (string, uint16, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, errors.New("invalid socket")
	}
	b, e := hex.DecodeString(a)
	if e != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0, errors.New("invalid socket address")
	}
	for i := 0; i < len(b); i += 4 {
		word, e := strconv.ParseUint(a[i*2:i*2+8], 16, 32)
		if e != nil {
			return "", 0, e
		}
		binary.NativeEndian.PutUint32(b[i:i+4], uint32(word))
	}
	port, e := strconv.ParseUint(p, 16, 16)
	return net.IP(b).String(), uint16(port), e
}
func Collect(ctx context.Context) (protocol.Listeners, error) {
	return collect(ctx, func(path string) (io.ReadCloser, error) { return os.Open(path) })
}
func collect(ctx context.Context, open func(string) (io.ReadCloser, error)) (protocol.Listeners, error) {
	out := protocol.Listeners{Coverage: "complete", Items: []protocol.Listener{}}
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		f, e := open("/proc/net/" + kind)
		if e != nil {
			out.Coverage = "partial"
			continue
		}
		out.Available = true
		e = read(ctx, f, kind, &out)
		f.Close()
		if e != nil {
			return out, e
		}
		if len(out.Items) >= 256 {
			out.Truncated = true
			out.Coverage = "partial"
			break
		}
	}
	if !out.Available {
		out.Coverage = "unavailable"
	}
	if out.Truncated && out.Available {
		out.Coverage = "partial"
	}
	return out, nil
}
func read(ctx context.Context, r io.Reader, kind string, out *protocol.Listeners) error {
	limited := &io.LimitedReader{R: r, N: 2 * 1024 * 1024}
	s := bufio.NewScanner(limited)
	s.Buffer(make([]byte, 4096), 8192)
	if !s.Scan() {
		out.Coverage = "partial"
		return s.Err()
	}
	lines := 0
	for s.Scan() {
		if e := ctx.Err(); e != nil {
			return e
		}
		lines++
		if lines > 8192 || len(out.Items) >= 256 {
			out.Truncated = true
			out.Coverage = "partial"
			break
		}
		f := strings.Fields(s.Text())
		if len(f) < 4 {
			out.Coverage = "partial"
			continue
		}
		want := "0A"
		if strings.HasPrefix(kind, "udp") {
			want = "07"
		}
		if f[3] != want {
			continue
		}
		addr, port, e := address(f[1])
		if e != nil || port == 0 {
			out.Coverage = "partial"
			continue
		}
		out.Items = append(out.Items, protocol.Listener{Protocol: kind, Address: addr, Port: port})
	}
	if limited.N == 0 {
		out.Truncated = true
		out.Coverage = "partial"
	}
	return s.Err()
}
