//go:build linux

package localfile

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

// systemd may grant credential access with a named-user POSIX ACL. Its mask
// appears as group-read in stat(2), although the owning group has no access.
// Accept only a root-owned, read-only file whose ACL grants read to this UID
// alone. A path name or environment variable never enables this exception.
func privateCredentialACL(f *os.File) bool {
	uid := os.Geteuid()
	if uid == 0 {
		return false
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != 0 || st.Mode&0777 != 0440 || st.Nlink != 1 {
		return false
	}
	var data [44]byte // version header plus exactly five ACL entries
	n, err := unix.Fgetxattr(int(f.Fd()), "system.posix_acl_access", data[:])
	return err == nil && n == len(data) && onlyReaderACL(data[:], uint32(uid))
}

func onlyReaderACL(data []byte, uid uint32) bool {
	if uid == 0 || len(data) != 44 || binary.LittleEndian.Uint32(data) != 2 {
		return false
	}
	const undefined = ^uint32(0)
	want := []struct {
		tag, permission uint16
		id              uint32
	}{{1, 4, undefined}, {2, 4, uid}, {4, 0, undefined}, {16, 4, undefined}, {32, 0, undefined}}
	for i, entry := range want {
		b := data[4+8*i:]
		if binary.LittleEndian.Uint16(b) != entry.tag || binary.LittleEndian.Uint16(b[2:]) != entry.permission || binary.LittleEndian.Uint32(b[4:]) != entry.id {
			return false
		}
	}
	return true
}
