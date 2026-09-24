package protocol

import (
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxDispatchResultBytes = 32 * 1024

type PollRequest struct {
	Version      int    `json:"version"`
	PolicyDigest string `json:"policy_digest"`
}

func DecodePoll(data []byte) (PollRequest, error) {
	var p PollRequest
	if err := strictjson.Decode(data, &p, 256, "version", "policy_digest"); err != nil {
		return p, err
	}
	if p.Version != Version || !identity.Hex(p.PolicyDigest, 64) {
		return p, errors.New("invalid poll request")
	}
	return p, nil
}

type ResultAck struct {
	Version      int    `json:"version"`
	AgentID      string `json:"agent_id"`
	Epoch        string `json:"epoch"`
	RequestID    string `json:"request_id"`
	ResultDigest string `json:"result_digest"`
}

func DecodeResultAck(data []byte) (ResultAck, error) {
	var a ResultAck
	if err := strictjson.Decode(data, &a, 1024, "version", "agent_id", "epoch", "request_id", "result_digest"); err != nil {
		return a, err
	}
	if a.Version != Version || !identity.Hex(a.AgentID, 32) || !identity.Hex(a.Epoch, 32) || !identity.Hex(a.RequestID, 32) || !identity.Hex(a.ResultDigest, 64) {
		return a, errors.New("invalid result acknowledgment")
	}
	return a, nil
}

func DecodeResult(data []byte) (Result, error) {
	var r Result
	if err := strictjson.Decode(data, &r, MaxResultBytes, "request_id", "agent_id", "epoch", "task_type", "started_at", "finished_at", "status", "data", "error_code", "truncated", "policy_digest"); err != nil {
		return r, err
	}
	return r, r.Validate()
}
func (r Result) Validate() error {
	bad := errors.New("invalid task result")
	if !identity.Hex(r.RequestID, 32) || !identity.Hex(r.AgentID, 32) || !identity.Hex(r.Epoch, 32) || !identity.Hex(r.PolicyDigest, 64) || r.StartedAt <= 0 || r.FinishedAt < r.StartedAt || r.Truncated {
		return bad
	}
	if !KnownTask(r.Type) {
		return bad
	}
	if r.Status == Succeeded {
		if r.ErrorCode != "" {
			return bad
		}
		if r.Type == SystemInfo {
			i, err := DecodeInformation(r.Data)
			if err != nil {
				return err
			}
			return i.Validate(r.FinishedAt)
		}
		switch r.Type {
		case SystemMetrics:
			_, err := DecodeMeasurements(r.Data)
			return err
		case SSHAudit:
			_, err := DecodeSSHReport(r.Data, r.FinishedAt)
			return err
		case ServiceStatus:
			_, err := DecodeServiceReport(r.Data, r.FinishedAt)
			return err
		}
		return bad
	}
	valid := false
	switch r.Status {
	case Rejected:
		valid = r.ErrorCode == "paused" || r.ErrorCode == "task_disabled" || r.ErrorCode == "policy_mismatch" || r.ErrorCode == "rate_limited" || r.ErrorCode == "future" || r.ErrorCode == "resource_denied"
	case Expired:
		valid = r.ErrorCode == "expired"
	case Failed:
		valid = r.ErrorCode == "deadline" || r.ErrorCode == "collector_failed" || r.ErrorCode == "result_limit"
	case Indeterminate:
		valid = r.ErrorCode == "recovered_after_restart"
	}
	if !valid {
		return bad
	}
	var empty struct{}
	return strictjson.Decode(r.Data, &empty, 256)
}
