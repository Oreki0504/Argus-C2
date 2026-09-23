// Package localfile reads administrator-selected configuration files, not
// remotely supplied paths. Files and parent directories must be locally trusted.
package localfile

import (
	"errors"
	"os"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

func Read(path string, limit int, secret bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular, non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("configuration changed while opening")
	}
	if secret && runtime.GOOS != "windows" && after.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private key must not be accessible by group or others")
	}
	return strictjson.Read(f, limit)
}
