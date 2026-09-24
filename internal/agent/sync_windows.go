//go:build windows

package agent

// File contents are flushed individually. Windows directory sync is not exposed
// by os.File.Sync; installation must additionally restrict the directory ACL.
func syncDir(string) error { return nil }
