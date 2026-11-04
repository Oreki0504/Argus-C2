//go:build !linux

package localdb

func filesystemSpace(string) (uint64, uint64, bool, error) { return 0, 0, false, nil }
