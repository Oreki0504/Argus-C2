//go:build linux

package saferead

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
	"golang.org/x/sys/unix"
)

const noLinks = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

func classify(err error) string {
	switch {
	case errors.Is(err, unix.ENOENT):
		return "missing"
	case errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM):
		return "permission_denied"
	case errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.E2BIG):
		return "unsupported"
	case errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EAGAIN):
		return "unsafe_path"
	default:
		return "io_error"
	}
}
func trustedDir(fd int, uid uint32, ancestor bool) bool {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uid) {
		return false
	}
	// Root-owned sticky ancestors such as /tmp cannot be used to replace a
	// different user's checked child. The configured base itself must be private
	// from group/other writes even when it is sticky.
	return st.Mode&0022 == 0 || (ancestor && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)
}
func openBase(path string, uid uint32) (int, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	for i, part := range parts {
		next, err := unix.Openat2(fd, part, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: noLinks})
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
		if !trustedDir(fd, uid, i < len(parts)-1) {
			unix.Close(fd)
			return -1, unix.EACCES
		}
	}
	return fd, nil
}
func read(ctx context.Context, f resources.SSHFile) Observation {
	return readSnapshot(ctx, f, nil)
}

// afterRead is a package-private fault-injection seam for deterministic tests.
func readSnapshot(ctx context.Context, f resources.SSHFile, afterRead func()) Observation {
	base, err := openBase(f.BaseDir, f.OwnerUID)
	if err != nil {
		return Observation{Code: classify(err)}
	}
	defer unix.Close(base)
	// Validate every intermediate directory through pinned descriptors. The
	// final full-path open is also constrained beneath the original base.
	parent, err := unix.Dup(base)
	if err != nil {
		return Observation{Code: "io_error"}
	}
	parts := strings.Split(f.RelativePath, "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat2(parent, part, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: noLinks | unix.RESOLVE_NO_XDEV})
		unix.Close(parent)
		if err != nil {
			return Observation{Code: classify(err)}
		}
		parent = next
		if !trustedDir(parent, f.OwnerUID, false) {
			unix.Close(parent)
			return Observation{Code: "unsafe_path"}
		}
	}
	unix.Close(parent)
	fd, err := unix.Openat2(base, f.RelativePath, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC, Resolve: noLinks | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return Observation{Code: classify(err)}
	}
	file := os.NewFile(uintptr(fd), "SSH audit resource")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil {
		return Observation{Code: "io_error"}
	}
	o := Observation{MetadataAvailable: true, Metadata: protocol.FileMetadata{UID: before.Uid, GID: before.Gid, Mode: before.Mode & 07777, Size: max(before.Size, 0)}, Code: "ok"}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		o.Code = "unsafe_type"
		return o
	}
	if before.Uid != f.OwnerUID || before.Gid != f.OwnerGID {
		o.Code = "owner_mismatch"
		return o
	}
	if before.Size < 0 || before.Size > int64(f.MaxBytes) {
		o.Code = "too_large"
		return o
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(f.MaxBytes)+1))
	if afterRead != nil {
		afterRead()
	}
	if err != nil || ctx.Err() != nil {
		o.Code = "io_error"
		return o
	}
	if len(data) > f.MaxBytes {
		o.Code = "too_large"
		return o
	}
	if unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || before.Mode != after.Mode || before.Nlink != after.Nlink || before.Uid != after.Uid || before.Gid != after.Gid || int64(len(data)) != before.Size {
		o.Code = "changed_during_read"
		return o
	}
	check, err := unix.Openat2(base, f.RelativePath, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: noLinks | unix.RESOLVE_NO_XDEV})
	if err != nil {
		o.Code = "changed_during_read"
		return o
	}
	defer unix.Close(check)
	var current unix.Stat_t
	if unix.Fstat(check, &current) != nil || current.Dev != before.Dev || current.Ino != before.Ino {
		o.Code = "changed_during_read"
		return o
	}
	o.Data = data
	return o
}
