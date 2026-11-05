package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestPrunedUnknownBecomesHeldWithoutRecollection(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	job, _ := pendingResult(t, f, r)
	old := time.Now().Add(-91 * 24 * time.Hour).Unix()
	if _, err := f.store.DB.Exec("UPDATE tasks SET status='UNKNOWN',dispatch_expires_at=?,result_due_at=? WHERE id=?", old, old, job.ID); err != nil {
		t.Fatal(err)
	}
	p, err := f.store.Prune(t.Context(), 30, 90, 200, filepath.Join(t.TempDir(), "before-prune.db"))
	if err != nil || p.Deleted != 1 {
		t.Fatal(p, err)
	}
	if err = r.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	record, err := r.Engine.State.Delivery(t.Context(), job.ID)
	if err != nil || record.Delivery != "held" || record.Reason != "task_not_found" || record.Bytes == 0 {
		t.Fatal(record, err)
	}
	if _, err = r.Engine.Process(t.Context(), job, func(context.Context, string) error { t.Fatal("held task requested another grant"); return nil }); !errors.Is(err, agent.ErrResultHeld) {
		t.Fatal(err)
	}
}

func TestGrantFailureReconcilesAfterServerStopsRedelivery(t *testing.T) {
	for _, kind := range []string{"rejected", "lost-grant-response", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			f := newFleet(t)
			r := f.enroll("agent", policy.Default())
			job := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
			calls := 0
			r.Engine.Execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) { calls++; return nil, nil }
			base := r.Client.Transport
			r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if strings.HasSuffix(req.URL.Path, "/running") {
					if kind == "lost-grant-response" {
						res, err := base.RoundTrip(req)
						if err != nil {
							return nil, err
						}
						res.Body.Close()
						return nil, io.ErrUnexpectedEOF
					}
					if kind == "timeout" {
						return nil, context.DeadlineExceeded
					}
					return &http.Response{StatusCode: 409, Header: http.Header{"Content-Type": []string{"application/json"}, protocol.VersionHeader: []string{"1"}}, Body: io.NopCloser(strings.NewReader(`{"error":"denied","code":"state_conflict"}`)), Request: req}, nil
				}
				return base.RoundTrip(req)
			})
			if err := r.Step(t.Context()); err == nil {
				t.Fatal("grant failure hidden")
			}
			r.Client.Transport = base
			if _, err := f.store.DB.Exec("UPDATE tasks SET result_due_at=? WHERE id=?", time.Now().Unix()-1, job.ID); err != nil {
				t.Fatal(err)
			}
			v, err := f.store.Task(t.Context(), job.ID)
			if err != nil || v.Task.Status != protocol.Unknown || v.Result != nil {
				t.Fatal(v, err)
			}
			if err = r.Step(t.Context()); err != nil {
				t.Fatal("normal cycle could not reconcile", err)
			}
			d, err := r.Engine.State.Delivery(t.Context(), job.ID)
			if err != nil || d.Delivery != "acknowledged" {
				t.Fatal(d, err)
			}
			if calls != 0 {
				t.Fatal("grant recovery collected", calls)
			}
		})
	}
}
