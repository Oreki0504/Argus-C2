package integration

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestRenewalFailureKeepsValidCertificateOnline(t *testing.T) {
	for _, kind := range []string{"server-error", "disconnect", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			f := newFleet(t)
			f.issuer.Lifetime = 6 * 24 * time.Hour
			r := f.enroll("agent", policy.Default())
			job, _ := pendingResult(t, f, r)
			next := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
			base := r.Client.Transport
			renewals, heartbeats := 0, 0
			r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/v1/agent/renew" {
					renewals++
					switch kind {
					case "disconnect":
						return nil, io.ErrUnexpectedEOF
					case "timeout":
						deadline, ok := req.Context().Deadline()
						if !ok || time.Until(deadline) > 6*time.Second {
							t.Error("renewal has no independent budget")
						}
						return nil, context.DeadlineExceeded
					default:
						return &http.Response{StatusCode: 500, Header: http.Header{"Content-Type": []string{"application/json"}, protocol.VersionHeader: []string{"1"}}, Body: io.NopCloser(strings.NewReader(`{"error":"unavailable","code":"operation_failed"}`)), Request: req}, nil
					}
				}
				if req.URL.Path == "/v1/agent/heartbeat" {
					heartbeats++
				}
				return base.RoundTrip(req)
			})
			for range 2 {
				if err := r.Step(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if renewals != 1 || heartbeats != 2 {
				t.Fatal("renewal retry blocked/thrashed cycle", renewals, heartbeats)
			}
			record, err := r.Engine.State.Delivery(t.Context(), job.ID)
			if err != nil || record.Delivery != "acknowledged" {
				t.Fatal(record, err)
			}
			view, err := f.store.Task(t.Context(), next.ID)
			if err != nil || view.Result == nil || view.Task.Status != protocol.Succeeded {
				t.Fatal(view, err)
			}
			if err = f.store.Disable(t.Context(), "admin", r.Engine.State.NodeID); err != nil {
				t.Fatal(err)
			}
			if err = r.Step(t.Context()); err == nil || errors.Is(err, context.Canceled) {
				t.Fatal("revocation bypassed", err)
			}
		})
	}
}
