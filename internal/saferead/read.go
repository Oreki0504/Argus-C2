// Package saferead only reads explicitly mapped SSH audit files.
package saferead

import (
	"context"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

type Observation struct {
	Data              []byte
	Metadata          protocol.FileMetadata
	MetadataAvailable bool
	Code              string
}

func Read(ctx context.Context, f resources.SSHFile) Observation {
	if f.Validate() != nil {
		return Observation{Code: "unsafe_path"}
	}
	if ctx.Err() != nil {
		return Observation{Code: "io_error"}
	}
	return read(ctx, f)
}
