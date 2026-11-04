// Package collectors is the complete, fixed read-only task registry.
package collectors

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/collectors/network"
	"github.com/Oreki0504/Argus-C2/internal/collectors/process"
	"github.com/Oreki0504/Argus-C2/internal/collectors/services"
	"github.com/Oreki0504/Argus-C2/internal/collectors/ssh"
	"github.com/Oreki0504/Argus-C2/internal/collectors/system"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func Execute(ctx context.Context, t protocol.Task, p policy.Policy) (json.RawMessage, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := t.Validate(); e != nil {
		return nil, e
	}
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if !p.Allows(t) {
		return nil, errors.New("local policy denies task")
	}
	var value any
	var e error
	switch t.Type {
	case protocol.SystemInfo:
		value, e = collector.Information(ctx)
	case protocol.SystemMetrics:
		value, e = collector.Measurements(ctx, p.Telemetry)
	case protocol.ServiceStatus:
		id, _ := t.Resource()
		v, _ := p.Service(id)
		value, e = service.Collect(ctx, v)
	case protocol.SSHAudit:
		id, _ := t.Resource()
		v, _ := p.SSHProfile(id)
		value, e = sshaudit.Collect(ctx, v)
	case protocol.ProcessList:
		value, e = process.Collect(ctx)
	case protocol.NetworkListeners:
		value, e = network.Collect(ctx)
	default:
		return nil, errors.New("unregistered collector")
	}
	if e != nil {
		return nil, e
	}
	return json.Marshal(value)
}
