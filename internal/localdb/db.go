// Package localdb opens bounded, private, operator-selected SQLite state.
package localdb

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite"
)

func PrivateFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return errors.New("state files must be private regular files")
	}
	return nil
}

// Existing callers fail if the directory or database is missing. In particular,
// losing probe replay state must never silently create an empty replacement.
func Open(dir, name string, create bool) (*sql.DB, error) {
	if name != "argus.db" && name != "probe.db" {
		return nil, errors.New("unknown state database")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if create {
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("state directory must be private and operator-controlled")
	}
	path := filepath.Join(dir, name)
	if create {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			err = f.Close()
		}
		if err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		err := PrivateFile(path + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
	}
	p := filepath.ToSlash(path)
	if runtime.GOOS == "windows" {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(2000)", "foreign_keys(1)", "journal_mode(WAL)", "synchronous(FULL)"}, "_txlock": {"immediate"}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// Lock is held for the full lifetime of the probe worker; the OS releases it on
// a crash. A second process cannot mistake another worker's tasks for crashes.
func Lock(dir string) (*os.File, error) {
	path := filepath.Join(dir, "probe.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if os.IsExist(err) {
		if err := PrivateFile(path); err != nil {
			return nil, err
		}
		f, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, errors.New("another probe worker holds the state lock")
	}
	return f, nil
}
