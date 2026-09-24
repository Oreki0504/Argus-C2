package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestResultAcknowledgmentCannotDiscardUnmatchedData(t *testing.T) {
	n := identity.New()
	now := time.Now().Unix()
	r := protocol.Result{RequestID: identity.RandomID(), AgentID: n.AgentID, Epoch: n.EnrollmentEpoch, Type: protocol.SystemInfo, StartedAt: now, FinishedAt: now, Status: protocol.Failed, Data: json.RawMessage(`{}`), ErrorCode: "deadline", PolicyDigest: strings.Repeat("a", 64)}
	data, _ := json.Marshal(r)
	ack := protocol.ResultAck{Version: 1, AgentID: n.AgentID, Epoch: n.EnrollmentEpoch, RequestID: r.RequestID, ResultDigest: audit.Digest(data)}
	for _, name := range []string{"valid", "digest", "node", "epoch", "request", "unknown_field", "duplicate", "oversize", "media", "status"} {
		t.Run(name, func(t *testing.T) {
			a := ack
			status := 200
			media := "application/json"
			switch name {
			case "digest":
				a.ResultDigest = strings.Repeat("0", 64)
			case "node":
				a.AgentID = identity.RandomID()
			case "epoch":
				a.Epoch = identity.RandomID()
			case "request":
				a.RequestID = identity.RandomID()
			case "media":
				media = "text/plain"
			case "status":
				status = 302
			}
			body, _ := json.Marshal(a)
			if name == "unknown_field" {
				body = append(body[:len(body)-1], []byte(`,"accepted":true}`)...)
			}
			if name == "duplicate" {
				body = append(body[:len(body)-1], []byte(`,"version":1}`)...)
			}
			if name == "oversize" {
				body = append([]byte(strings.Repeat(" ", 1025)), body...)
			}
			c := &Client{node: n, origin: "https://127.0.0.1", http: &http.Client{Transport: responseTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/api/v1/agent/results" || req.Method != "POST" {
					t.Error("unexpected endpoint")
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {media}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}}
			_, err := c.SubmitResult(t.Context(), data)
			if (err == nil) != (name == "valid") {
				t.Fatal("ack validation", err)
			}
		})
	}
}

func TestPollResponseIsBounded(t *testing.T) {
	c := &Client{node: identity.New(), origin: "https://127.0.0.1", http: &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", protocol.MaxEnvelopeBytes+1)))}, nil
	})}}
	if _, err := c.Poll(t.Context(), strings.Repeat("a", 64)); err == nil {
		t.Fatal("oversized signed envelope accepted")
	}
}
