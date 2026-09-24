//go:build !linux

package saferead

import (
	"context"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func read(context.Context, resources.SSHFile) Observation { return Observation{Code: "unsupported"} }
