// Package protocol defines strict versioned messages for the fixed task registry.
package protocol

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const (
	Version          = 1
	MaxEnvelopeBytes = 16 * 1024
	MaxPayloadBytes  = 8 * 1024
	MaxParamsBytes   = 4 * 1024
	MaxResultBytes   = 256 * 1024
	MaxLifetime      = 300
	MaxClockSkew     = 30
)

type TaskType string

const (
	SystemInfo    TaskType = "system.info"
	SystemMetrics TaskType = "system.metrics"
)

type Task struct {
	Version         int             `json:"version"`
	RequestID       string          `json:"request_id"`
	AgentID         string          `json:"agent_id"`
	EnrollmentEpoch string          `json:"enrollment_epoch"`
	CreatedAt       int64           `json:"created_at"`
	ExpiresAt       int64           `json:"expires_at"`
	Type            TaskType        `json:"task_type"`
	TaskVersion     int             `json:"task_version"`
	Params          json.RawMessage `json:"params"`
	ActorID         string          `json:"actor_id"`
	PolicyDigest    string          `json:"policy_digest"`
}

func DecodeTask(data []byte) (Task, error) {
	var task Task
	err := strictjson.Decode(data, &task, MaxPayloadBytes, "version", "request_id", "agent_id", "enrollment_epoch", "created_at", "expires_at", "task_type", "task_version", "params", "actor_id", "policy_digest")
	if err != nil {
		return Task{}, err
	}
	return task, task.Validate()
}

func (t Task) Validate() error {
	if t.Version != Version || t.TaskVersion != 1 {
		return errors.New("unsupported protocol or task version")
	}
	if !identity.Hex(t.RequestID, 32) || !identity.Hex(t.PolicyDigest, 64) || (identity.Node{AgentID: t.AgentID, EnrollmentEpoch: t.EnrollmentEpoch}).Validate() != nil {
		return errors.New("invalid task identity or policy digest")
	}
	if !identifier(t.ActorID) {
		return errors.New("invalid actor identifier")
	}
	// Positive timestamps make subtraction safe after checking their order.
	if t.CreatedAt <= 0 || t.ExpiresAt <= t.CreatedAt || t.ExpiresAt-t.CreatedAt > MaxLifetime {
		return errors.New("invalid task validity window")
	}
	switch t.Type {
	case SystemInfo, SystemMetrics:
		var params struct{}
		if err := strictjson.Decode(t.Params, &params, MaxParamsBytes); err != nil {
			return err
		}
	default:
		return errors.New("unsupported task type")
	}
	return nil
}

// CheckTarget is preflight only; the probe's policy and durable acceptance gate
// are still required before any handler may run.
func (t Task) CheckTarget(node identity.Node, policyDigest string, now time.Time) error {
	if err := t.Validate(); err != nil {
		return err
	}
	if node.Validate() != nil || !identity.Hex(policyDigest, 64) || t.AgentID != node.AgentID || t.EnrollmentEpoch != node.EnrollmentEpoch || t.PolicyDigest != policyDigest {
		return errors.New("task target or policy mismatch")
	}
	current := now.Unix()
	if current >= t.ExpiresAt || current < t.CreatedAt-MaxClockSkew {
		return errors.New("expired or future task")
	}
	return nil
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

type ErrorCode string

const (
	Unauthorized     ErrorCode = "unauthorized"
	InvalidRequest   ErrorCode = "invalid_request"
	NotFound         ErrorCode = "not_found"
	MethodNotAllowed ErrorCode = "method_not_allowed"
)

type ErrorResponse struct {
	Code ErrorCode `json:"code"`
}

// ConnectionInfo describes the mutually authenticated peer, not a heartbeat.
type ConnectionInfo struct {
	Version         int    `json:"version"`
	AgentID         string `json:"agent_id"`
	EnrollmentEpoch string `json:"enrollment_epoch"`
}

func DecodeConnectionInfo(data []byte) (ConnectionInfo, error) {
	var info ConnectionInfo
	if err := strictjson.Decode(data, &info, 4096, "version", "agent_id", "enrollment_epoch"); err != nil {
		return info, err
	}
	if info.Version != Version {
		return info, errors.New("unsupported protocol version")
	}
	return info, (identity.Node{AgentID: info.AgentID, EnrollmentEpoch: info.EnrollmentEpoch}).Validate()
}

type TaskStatus string

const (
	Accepted      TaskStatus = "accepted"
	Running       TaskStatus = "running"
	Succeeded     TaskStatus = "succeeded"
	Failed        TaskStatus = "failed"
	Rejected      TaskStatus = "rejected"
	Expired       TaskStatus = "expired"
	Indeterminate TaskStatus = "indeterminate"
)

// Result carries a terminal outcome; actual policy and assignment are checked
// independently by the probe and server.
type Result struct {
	RequestID    string          `json:"request_id"`
	AgentID      string          `json:"agent_id"`
	Epoch        string          `json:"epoch"`
	Type         TaskType        `json:"task_type"`
	StartedAt    int64           `json:"started_at"`
	FinishedAt   int64           `json:"finished_at"`
	Status       TaskStatus      `json:"status"`
	Data         json.RawMessage `json:"data"`
	ErrorCode    ErrorCode       `json:"error_code"`
	Truncated    bool            `json:"truncated"`
	PolicyDigest string          `json:"policy_digest"`
}
