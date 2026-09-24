package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/collector"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

func (c *Client) Poll(ctx context.Context, digest string) ([]byte, error) {
	data, err := json.Marshal(protocol.PollRequest{Version: 1, PolicyDigest: digest})
	if err != nil {
		return nil, err
	}
	if _, err := protocol.DecodePoll(data); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/v1/agent/tasks/poll", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("server rejected task poll")
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, errors.New("expected JSON task envelope")
	}
	return strictjson.Read(resp.Body, protocol.MaxEnvelopeBytes)
}
func (c *Client) SubmitResult(ctx context.Context, data []byte) (protocol.ResultAck, error) {
	r, err := protocol.DecodeResult(data)
	if err != nil {
		return protocol.ResultAck{}, err
	}
	if r.AgentID != c.node.AgentID || r.Epoch != c.node.EnrollmentEpoch || len(data) > protocol.MaxDispatchResultBytes {
		return protocol.ResultAck{}, errors.New("local result target or size mismatch")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/v1/agent/results", bytes.NewReader(data))
	if err != nil {
		return protocol.ResultAck{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return protocol.ResultAck{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.ResultAck{}, errors.New("server rejected task result")
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return protocol.ResultAck{}, errors.New("expected JSON result acknowledgment")
	}
	dataAck, err := strictjson.Read(resp.Body, 1024)
	if err != nil {
		return protocol.ResultAck{}, err
	}
	a, err := protocol.DecodeResultAck(dataAck)
	if err != nil {
		return a, err
	}
	if a.AgentID != r.AgentID || a.Epoch != r.Epoch || a.RequestID != r.RequestID || a.ResultDigest != audit.Digest(data) {
		return a, errors.New("result acknowledgment mismatch")
	}
	return a, nil
}

func (c *Client) flush(ctx context.Context, s *probe.State) error {
	data, err := s.Pending(ctx)
	if err != nil || len(data) == 0 {
		return err
	}
	ack, err := c.SubmitResult(ctx, data)
	if err != nil {
		return err
	}
	return s.Acknowledge(ctx, ack.RequestID, ack.ResultDigest)
}

// RunTasks keeps telemetry available if task state is blocked. Policy is read
// every cycle and again by the engine immediately before a task is accepted.
// All retries transmit durable results; they never rerun a cached request.
func (c *Client) RunTasks(ctx context.Context, path string, s *probe.State, once bool, report func(string, error)) error {
	var engine *probe.Engine
	if s != nil {
		engine = probe.NewEngine(s, path, c.origin)
	}
	nextHeartbeat := time.Time{}
	failures := 0
	for {
		var cycleErr error
		p, err := policy.Load(path)
		if err != nil {
			return err
		}
		digest, err := p.Digest()
		if err != nil {
			return err
		}
		mode := "ready"
		if s == nil {
			mode = "blocked"
			cycleErr = errors.New("task state is unavailable")
		} else if err := s.Ready(ctx, p, time.Now()); err != nil {
			mode = "blocked"
			cycleErr = err
			if report != nil {
				report("task_state", err)
			}
		} else if p.Paused {
			mode = "paused"
		}
		var networkErr error
		if !time.Now().Before(nextHeartbeat) {
			sampleCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			h, sampleErr := collector.Collect(sampleCtx, c.node, p.Telemetry)
			cancel()
			if sampleErr == nil {
				h.Version = protocol.TaskHeartbeatVersion
				h.PolicyDigest = digest
				h.TaskState = mode
				sampleErr = c.Heartbeat(ctx, h)
			}
			if report != nil {
				report("heartbeat", sampleErr)
			}
			if sampleErr != nil {
				networkErr = sampleErr
			} else {
				nextHeartbeat = time.Now().Add(jitter(time.Duration(p.Telemetry.IntervalSeconds) * time.Second))
			}
		}
		if s != nil {
			if err := c.flush(ctx, s); err != nil {
				networkErr = err
				if report != nil {
					report("result", err)
				}
			}
		}
		if networkErr == nil && mode == "ready" {
			envelope, pollErr := c.Poll(ctx, digest)
			if pollErr != nil {
				networkErr = pollErr
				if report != nil {
					report("poll", pollErr)
				}
			} else if len(envelope) > 0 {
				result, err := engine.Process(ctx, envelope)
				if err != nil {
					cycleErr = err
				}
				if report != nil {
					report("task", err)
				}
				if err == nil && len(result) > 0 {
					ack, err := c.SubmitResult(ctx, result)
					if err == nil {
						err = s.Acknowledge(ctx, ack.RequestID, ack.ResultDigest)
					}
					if err != nil {
						networkErr = err
					}
					if report != nil {
						report("result", err)
					}
				}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if once {
			return errors.Join(networkErr, cycleErr)
		}
		delay := time.Duration(p.PollSeconds) * time.Second
		if networkErr != nil {
			if failures < 16 {
				failures++
			}
			delay = retryDelay(failures)
		} else {
			failures = 0
		}
		timer := time.NewTimer(jitter(delay))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
