// Package protocol defines the small, unsigned HTTPS diagnostics protocol.
package protocol

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxPayloadBytes = 8192
const MaxDispatchResultBytes = 65536
const MaxResultBytes = MaxDispatchResultBytes
const MaxLifetime = 3600
const MaxClockSkew = 30
const MaxExecutionTimeoutMS = 30000
const ResultGraceSeconds = 60
const MaxUnixTime = 253402300799

type TaskType string

const (
	SystemInfo       TaskType = "system.info"
	SystemMetrics    TaskType = "system.metrics"
	ServiceStatus    TaskType = "service.status"
	NetworkListeners TaskType = "network.listeners"
	ProcessList      TaskType = "process.list"
	SSHAudit         TaskType = "ssh.audit"
)

type TaskStatus string

const (
	Pending   TaskStatus = "PENDING"
	Accepted  TaskStatus = "ACCEPTED"
	Running   TaskStatus = "RUNNING"
	Succeeded TaskStatus = "SUCCEEDED"
	Failed    TaskStatus = "FAILED"
	Unknown   TaskStatus = "UNKNOWN"
)

func Terminal(s TaskStatus) bool { return s == Succeeded || s == Failed || s == Unknown }

type Task struct {
	ID                 string          `json:"id"`
	NodeID             string          `json:"node_id"`
	Type               TaskType        `json:"task_type"`
	Params             json.RawMessage `json:"parameters"`
	Status             TaskStatus      `json:"status"`
	CreatedAt          int64           `json:"created_at"`
	DispatchExpiresAt  int64           `json:"dispatch_expires_at"`
	ExecutionTimeoutMS int             `json:"execution_timeout_ms"`
	ResultDueAt        int64           `json:"result_due_at"`
}
type TaskRequest struct {
	NodeID             string          `json:"node_id"`
	Type               TaskType        `json:"task_type"`
	Params             json.RawMessage `json:"parameters"`
	TTLSeconds         int             `json:"ttl_seconds"`
	ExecutionTimeoutMS int             `json:"execution_timeout_ms"`
}
type Result struct {
	TaskID      string          `json:"task_id"`
	NodeID      string          `json:"node_id"`
	Status      TaskStatus      `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	Error       string          `json:"error"`
	CompletedAt int64           `json:"completed_at"`
}
type Node struct {
	AgentMetadata
	ID                     string `json:"id"`
	Hostname               string `json:"hostname"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	Status                 string `json:"status"`
	LastSeenAt             int64  `json:"last_seen_at"`
	CreatedAt              int64  `json:"created_at"`
	CertificateExpiresAt   int64  `json:"certificate_expires_at"`
}
type EnrollmentRequest struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	CSR      []byte `json:"csr"`
}
type EnrollmentResponse struct {
	NodeID      string `json:"node_id"`
	Certificate string `json:"certificate"`
}
type RenewalRequest struct {
	CSR []byte `json:"csr"`
}
type Heartbeat struct {
	Hostname string `json:"hostname"`
}

func KnownTask(t TaskType) bool {
	return t == SystemInfo || t == SystemMetrics || t == ServiceStatus || t == NetworkListeners || t == ProcessList || t == SSHAudit
}
func ResourceID(s string) bool {
	return len(s) <= 32 && identity.Valid(s) && s[0] != '_' && s[0] != '-'
}
func (t Task) Resource() (string, error) {
	var p struct {
		ServiceID string `json:"service_id"`
		ProfileID string `json:"profile_id"`
	}
	field := "service_id"
	if t.Type == SSHAudit {
		field = "profile_id"
	} else if t.Type != ServiceStatus {
		return "", errors.New("task has no resource")
	}
	if err := strictjson.Decode(t.Params, &p, 256, field); err != nil {
		return "", err
	}
	id := p.ServiceID
	if t.Type == SSHAudit {
		id = p.ProfileID
	}
	if !ResourceID(id) {
		return "", errors.New("invalid resource ID")
	}
	return id, nil
}
func ValidateParams(kind TaskType, p json.RawMessage) error {
	switch kind {
	case SystemInfo, SystemMetrics, ProcessList, NetworkListeners:
		return strictjson.Decode(p, &struct{}{}, 256)
	case ServiceStatus, SSHAudit:
		_, err := (Task{Type: kind, Params: p}).Resource()
		return err
	default:
		return errors.New("unsupported task type")
	}
}
func (t Task) Validate() error {
	if !identity.Valid(t.ID) || !identity.Valid(t.NodeID) || t.CreatedAt <= 0 || t.DispatchExpiresAt > MaxUnixTime || t.DispatchExpiresAt <= t.CreatedAt || t.DispatchExpiresAt-t.CreatedAt > MaxLifetime {
		return errors.New("invalid task identity or lifetime")
	}
	if t.ExecutionTimeoutMS < 1 || t.ExecutionTimeoutMS > MaxExecutionTimeoutMS || t.ResultDueAt <= t.CreatedAt || t.ResultDueAt > t.DispatchExpiresAt+MaxExecutionTimeoutMS/1000+ResultGraceSeconds {
		return errors.New("invalid execution budget or result due time")
	}
	if t.Status != Pending && t.Status != Accepted && t.Status != Running && !Terminal(t.Status) {
		return errors.New("invalid task status")
	}
	return ValidateParams(t.Type, t.Params)
}
func DecodeTask(b []byte) (Task, error) {
	var t Task
	if err := strictjson.Decode(b, &t, MaxPayloadBytes, "id", "node_id", "task_type", "parameters", "status", "created_at", "dispatch_expires_at", "execution_timeout_ms", "result_due_at"); err != nil {
		return t, err
	}
	return t, t.Validate()
}
func DecodeTaskRequest(b []byte) (TaskRequest, error) {
	var r TaskRequest
	if err := strictjson.Decode(b, &r, MaxPayloadBytes, "node_id", "task_type", "parameters", "ttl_seconds", "execution_timeout_ms"); err != nil {
		return r, err
	}
	if !identity.Valid(r.NodeID) || r.TTLSeconds < 10 || r.TTLSeconds > MaxLifetime || r.ExecutionTimeoutMS < 1 || r.ExecutionTimeoutMS > MaxExecutionTimeoutMS {
		return r, errors.New("invalid node or TTL")
	}
	return r, ValidateParams(r.Type, r.Params)
}
func (r Result) Validate() error {
	if !identity.Valid(r.TaskID) || !identity.Valid(r.NodeID) || !Terminal(r.Status) || !CleanText(r.Error, 128) || r.CompletedAt <= 0 || len(r.Payload) > MaxResultBytes-1024 {
		return errors.New("invalid result")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(r.Payload, &fields) != nil || fields == nil {
		return errors.New("result payload must be an object")
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	if err := strictjson.Decode(r.Payload, &fields, MaxResultBytes, names...); err != nil {
		return err
	}
	if r.Status == Succeeded && r.Error != "" || r.Status != Succeeded && len(fields) != 0 {
		return errors.New("invalid result outcome")
	}
	return nil
}
func DecodeResult(b []byte) (Result, error) {
	var r Result
	if err := strictjson.Decode(b, &r, MaxResultBytes, "task_id", "node_id", "status", "payload", "error", "completed_at"); err != nil {
		return r, err
	}
	return r, r.Validate()
}
func (r Result) CheckAssignment(t Task) error {
	if r.TaskID != t.ID || r.NodeID != t.NodeID {
		return errors.New("result assignment mismatch")
	}
	if r.Status != Succeeded {
		return nil
	}
	switch t.Type {
	case SystemInfo:
		v, e := DecodeInformation(r.Payload)
		if e != nil {
			return e
		}
		return v.Validate(r.CompletedAt)
	case SystemMetrics:
		_, e := DecodeMeasurements(r.Payload)
		return e
	case SSHAudit:
		v, e := DecodeSSHReport(r.Payload, r.CompletedAt)
		if e != nil {
			return e
		}
		id, _ := t.Resource()
		if v.ProfileID != id {
			return errors.New("SSH profile mismatch")
		}
	case ServiceStatus:
		v, e := DecodeServiceReport(r.Payload, r.CompletedAt)
		if e != nil {
			return e
		}
		id, _ := t.Resource()
		if v.ServiceID != id {
			return errors.New("service mismatch")
		}
	case ProcessList:
		return ValidateProcesses(r.Payload)
	case NetworkListeners:
		return ValidateListeners(r.Payload)
	default:
		return errors.New("unsupported result")
	}
	return nil
}
func NewResult(t Task, s TaskStatus, code string) Result {
	return Result{TaskID: t.ID, NodeID: t.NodeID, Status: s, Payload: json.RawMessage(`{}`), Error: code, CompletedAt: time.Now().Unix()}
}
