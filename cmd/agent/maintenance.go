package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/identity"
)

func maintain(ctx context.Context, s *agent.State, command, id, after, out, confirm string, input io.Reader, output, diagnostics io.Writer) error {
	encode := func(v any) error { return json.NewEncoder(output).Encode(v) }
	if command == "results" {
		rows, e := s.Deliveries(ctx, after)
		if e != nil {
			return e
		}
		return encode(rows)
	}
	if !identity.Valid(id) {
		return errors.New("-task requires one valid local task ID")
	}
	switch command {
	case "result-export":
		b, e := s.ResultBytes(ctx, id)
		if e != nil {
			return e
		}
		if out == "" {
			return errors.New("-out is required")
		}
		f, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(append(b, '\n'))
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		return encode(map[string]string{"task_id": id, "exported_to": out})
	case "result-retry":
		if e := s.Retry(ctx, id); e != nil {
			return e
		}
		return encode(map[string]string{"task_id": id, "delivery": "pending"})
	case "result-discard":
		record, e := s.Delivery(ctx, id)
		if e != nil {
			return e
		}
		if e = json.NewEncoder(diagnostics).Encode(record); e != nil {
			return e
		}
		fmt.Fprintln(diagnostics, "Server state: unknown (offline maintenance). Discard removes the local report permanently; it does not cancel the server task or acknowledge delivery. The server may remain UNKNOWN. Deduplication will be retained.")
		if confirm != "" {
			if confirm != id {
				return errors.New("-confirm-task must exactly match -task")
			}
		} else {
			fmt.Fprintf(diagnostics, "Type the task ID %s to confirm discard: ", id)
			scan := bufio.NewScanner(io.LimitReader(input, 256))
			scan.Buffer(make([]byte, 128), 256)
			if !scan.Scan() || strings.TrimSpace(scan.Text()) != id {
				return errors.New("discard not confirmed; result retained")
			}
		}
		if e = s.Discard(ctx, id); e != nil {
			return e
		}
		return encode(map[string]string{"task_id": id, "delivery": "discarded", "server_state": "unknown"})
	default:
		return errors.New("unknown local maintenance command")
	}
}
