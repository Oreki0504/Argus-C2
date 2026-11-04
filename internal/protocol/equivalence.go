package protocol

import (
	"encoding/json"
	"errors"
	"reflect"
)

// EquivalentResults compares validated typed reports, preserving exact integer
// counters and array order. It never normalizes timestamps or error codes.
func EquivalentResults(t Task, a, b Result) (bool, error) {
	for _, r := range []Result{a, b} {
		if err := errors.Join(r.Validate(), r.CheckAssignment(t)); err != nil {
			return false, err
		}
	}
	if a.TaskID != b.TaskID || a.NodeID != b.NodeID || a.Status != b.Status || a.Error != b.Error || a.CompletedAt != b.CompletedAt {
		return false, nil
	}
	if a.Status != Succeeded {
		return true, nil // Both payloads were validated as empty objects.
	}
	decode := func(raw json.RawMessage) (any, error) {
		var v any
		switch t.Type {
		case SystemInfo:
			v = &SystemInformation{}
		case SystemMetrics:
			v = &SystemMeasurements{}
		case ServiceStatus:
			v = &ServiceReport{}
		case SSHAudit:
			v = &SSHReport{}
		case ProcessList:
			v = &Processes{}
		case NetworkListeners:
			v = &Listeners{}
		default:
			return nil, errors.New("unsupported report type")
		}
		return v, json.Unmarshal(raw, v)
	}
	left, err := decode(a.Payload)
	if err != nil {
		return false, err
	}
	right, err := decode(b.Payload)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(left, right), nil
}

// SameAssignment excludes server-owned state/deadline observations, which may
// change on redelivery. Task parameters and execution budgets remain immutable.
func SameAssignment(a, b Task) bool {
	if a.ID != b.ID || a.NodeID != b.NodeID || a.Type != b.Type || a.CreatedAt != b.CreatedAt || a.DispatchExpiresAt != b.DispatchExpiresAt || a.ExecutionTimeoutMS != b.ExecutionTimeoutMS {
		return false
	}
	if ValidateParams(a.Type, a.Params) != nil || ValidateParams(b.Type, b.Params) != nil {
		return false
	}
	if a.Type == ServiceStatus || a.Type == SSHAudit {
		x, _ := a.Resource()
		y, _ := b.Resource()
		return x == y
	}
	return true
}
