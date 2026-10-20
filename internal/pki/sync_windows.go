//go:build windows

package pki

// Files are synced individually. Portable directory fsync is unavailable here.
func syncDirectory(string) error { return nil }
