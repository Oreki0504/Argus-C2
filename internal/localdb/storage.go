package localdb

import (
	"errors"
	"os"
	"path/filepath"
)

// Storage reports physical files, separately from logical result capacity.
type Storage struct {
	DatabaseBytes       int64  `json:"database_bytes"`
	WALBytes            int64  `json:"wal_bytes"`
	FilesystemAvailable bool   `json:"filesystem_available"`
	AvailableBytes      uint64 `json:"available_bytes"`
	TotalBytes          uint64 `json:"total_bytes"`
	Warning             bool   `json:"space_warning"`
}

func InspectStorage(dir, name string) (Storage, error) {
	var out Storage
	if name != "argus.db" && name != "probe.db" {
		return out, errors.New("unknown state database")
	}
	for _, suffix := range []string{"", "-wal"} {
		st, e := os.Lstat(filepath.Join(dir, name+suffix))
		if suffix != "" && os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return out, e
		}
		if !st.Mode().IsRegular() {
			return out, errors.New("database storage must be regular files")
		}
		if suffix == "" {
			out.DatabaseBytes = st.Size()
		} else {
			out.WALBytes = st.Size()
		}
	}
	available, total, ok, e := filesystemSpace(dir)
	if e != nil {
		return out, e
	}
	out.AvailableBytes, out.TotalBytes, out.FilesystemAvailable = available, total, ok
	// Operational warning only, never a promise that subsequent writes succeed.
	out.Warning = ok && (available < 64*1024*1024 || total > 0 && available < total/10)
	return out, nil
}
