//go:build !windows

package localdb

import (
	"os"

	"golang.org/x/sys/unix"
)

func lock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
