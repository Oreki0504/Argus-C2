//go:build !linux

package service

import (
	"context"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func query(context.Context, resources.Service) protocol.ServiceReport {
	return protocol.ServiceReport{Code: "unsupported"}
}
