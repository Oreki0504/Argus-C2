//go:build !linux

package network

import (
	"context"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func Collect(ctx context.Context) (protocol.Listeners, error) {
	return protocol.Listeners{Coverage: "unavailable", Items: []protocol.Listener{}}, ctx.Err()
}
