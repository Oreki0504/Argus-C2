//go:build linux

package localdb

import "golang.org/x/sys/unix"

func filesystemSpace(dir string) (available, total uint64, ok bool, err error) {
	var st unix.Statfs_t
	if err = unix.Statfs(dir, &st); err != nil {
		return 0, 0, false, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), true, nil
}
