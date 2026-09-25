//go:build !windows

package adminclient

// On Unix, the session file is protected by its 0600 file / 0700 directory.
func seal(b []byte) ([]byte, error)   { return append([]byte{}, b...), nil }
func unseal(b []byte) ([]byte, error) { return append([]byte{}, b...), nil }
