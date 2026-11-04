//go:build !linux

package process

import (
	"context"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func Collect(ctx context.Context) (protocol.Processes, error) {
	return protocol.Processes{Items: []protocol.Process{}}, ctx.Err()
}
