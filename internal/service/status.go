// Package service queries fixed read-only systemd properties, without commands.
package service

import (
	"context"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func Collect(ctx context.Context, s resources.Service) (protocol.ServiceReport, error) {
	if err := s.Validate(); err != nil {
		return protocol.ServiceReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return protocol.ServiceReport{}, err
	}
	r := query(ctx, s)
	r.ServiceID = s.ID
	r.ObservedAt = time.Now().Unix()
	return r, ctx.Err()
}
