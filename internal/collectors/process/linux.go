//go:build linux

// Package process reports bounded process metadata, never command lines or environments.
package process

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func Collect(ctx context.Context) (protocol.Processes, error) {
	dir, e := os.Open("/proc")
	if e != nil {
		return protocol.Processes{Items: []protocol.Process{}}, ctx.Err()
	}
	defer dir.Close()
	return collect(ctx, dir.Readdirnames, func(name string) ([]byte, error) {
		return localfile.Read("/proc/"+name+"/status", 16384, false)
	})
}

func collect(ctx context.Context, namesPage func(int) ([]string, error), status func(string) ([]byte, error)) (protocol.Processes, error) {
	out := protocol.Processes{Items: []protocol.Process{}}
	scanned := 0
	for {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		names, e := namesPage(128)
		if len(names) > 0 || e == nil || errors.Is(e, io.EOF) {
			out.Available = true
		}
		for _, name := range names {
			if e := ctx.Err(); e != nil {
				return out, e
			}
			scanned++
			if scanned > 8192 || len(out.Items) >= 256 {
				out.Truncated = true
				return out, ctx.Err()
			}
			pid, e := strconv.Atoi(name)
			if e != nil || pid <= 0 {
				continue
			}
			b, e := status(name)
			if e != nil {
				out.Truncated = true
				continue
			}
			if p, ok := parse(pid, string(b)); ok {
				out.Items = append(out.Items, p)
			} else {
				out.Truncated = true
			}
		}
		if errors.Is(e, io.EOF) {
			return out, ctx.Err()
		}
		if e != nil {
			out.Truncated = true
			return out, ctx.Err()
		}
	}
}
func parse(pid int, s string) (protocol.Process, bool) {
	p := protocol.Process{PID: pid}
	uid := false
	for _, line := range strings.Split(s, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(val)
		if len(f) == 0 {
			continue
		}
		switch key {
		case "Name":
			p.Name = strings.TrimSpace(val)
		case "State":
			p.State = f[0]
		case "Uid":
			v, e := strconv.ParseUint(f[0], 10, 32)
			if e == nil {
				p.UID = uint32(v)
				uid = true
			}
		}
	}
	return p, pid > 0 && uid && p.Name != "" && protocol.CleanText(p.Name, 64) && len(p.State) == 1 && strings.ContainsAny(p.State, "RSDZTtXxKWPI")
}
