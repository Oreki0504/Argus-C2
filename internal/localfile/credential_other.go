//go:build !linux

package localfile

import "os"

func privateCredentialACL(*os.File) bool { return false }
