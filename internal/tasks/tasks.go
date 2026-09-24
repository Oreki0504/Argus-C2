// Package tasks contains the entire executable registry. Only native read-only
// collectors are reachable; there is no dynamic handler or command interface.
package tasks

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/collector"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/service"
	"github.com/Oreki0504/Argus-C2/internal/sshaudit"
)

func Execute(ctx context.Context, t protocol.Task, p policy.Policy) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !p.Allows(t.Type) || !p.AllowsResource(t) {
		return nil, errors.New("local policy denies task")
	}
	switch t.Type {
	case protocol.SystemInfo:
		value, err := collector.Information(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	case protocol.SystemMetrics:
		value, err := collector.Measurements(ctx, p.Telemetry)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	case protocol.SSHAudit:
		id, _ := t.Resource()
		profile, _ := p.SSHProfile(id)
		value, err := sshaudit.Collect(ctx, profile)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	case protocol.ServiceStatus:
		id, _ := t.Resource()
		mapping, _ := p.Service(id)
		value, err := service.Collect(ctx, mapping)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	default:
		return nil, errors.New("unregistered task type")
	}
}
