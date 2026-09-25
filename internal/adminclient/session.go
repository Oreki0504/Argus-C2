package adminclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type SavedSession struct {
	Version int         `json:"version"`
	Origin  string      `json:"origin"`
	CAHash  string      `json:"ca_sha256"`
	Login   state.Login `json:"login"`
}

func sessionDir(dir string, create bool) (string, error) {
	if dir == "" {
		return "", errors.New("explicit -session directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if create {
		if err := os.Mkdir(abs, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return "", errors.New("session directory must be private and locally controlled")
	}
	return filepath.Join(abs, "session.bin"), nil
}
func PrepareSession(dir string) error {
	path, err := sessionDir(dir, true)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return errors.New("session file already exists; log out or explicitly forget it first")
	}
	return nil
}
func (c *Client) SaveSession(dir string, login state.Login) error {
	path, err := sessionDir(dir, false)
	if err != nil {
		return err
	}
	data, err := json.Marshal(SavedSession{1, c.Origin, c.CAHash, login})
	if err != nil {
		return err
	}
	defer clear(data)
	encrypted, err := seal(data)
	if err != nil {
		return err
	}
	defer clear(encrypted)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encrypted); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
func (c *Client) LoadSession(dir string) (state.Login, error) {
	path, err := sessionDir(dir, false)
	if err != nil {
		return state.Login{}, err
	}
	encrypted, err := localfile.Read(path, 8192, true)
	if err != nil {
		return state.Login{}, err
	}
	defer clear(encrypted)
	data, err := unseal(encrypted)
	if err != nil {
		return state.Login{}, errors.New("could not unlock the local session")
	}
	defer clear(data)
	var value struct {
		Version int             `json:"version"`
		Origin  string          `json:"origin"`
		CAHash  string          `json:"ca_sha256"`
		Login   json.RawMessage `json:"login"`
	}
	if err := strictjson.Decode(data, &value, 4096, "version", "origin", "ca_sha256", "login"); err != nil {
		return state.Login{}, errors.New("invalid local session")
	}
	if value.Version != 1 || value.Origin != c.Origin || value.CAHash != c.CAHash {
		return state.Login{}, errors.New("session belongs to a different server or trust bundle")
	}
	return decodeLogin(value.Login)
}
func ForgetSession(dir string) error {
	path, err := sessionDir(dir, false)
	if err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("session must be a regular file")
	}
	return os.Remove(path)
}
