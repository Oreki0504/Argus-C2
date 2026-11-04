package localdb

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStorageReportsDatabaseWALAndSpace(t *testing.T) {
	dir := t.TempDir()
	db := []byte("database")
	wal := []byte("committed WAL")
	if e := os.WriteFile(filepath.Join(dir, "argus.db"), db, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "argus.db-wal"), wal, 0600); e != nil {
		t.Fatal(e)
	}
	report, e := InspectStorage(dir, "argus.db")
	if e != nil || report.DatabaseBytes != int64(len(db)) || report.WALBytes != int64(len(wal)) {
		t.Fatal(report, e)
	}
	if runtime.GOOS == "linux" && (!report.FilesystemAvailable || report.TotalBytes == 0) {
		t.Fatal(report)
	}
	if e = os.Remove(filepath.Join(dir, "argus.db-wal")); e != nil {
		t.Fatal(e)
	}
	report, e = InspectStorage(dir, "argus.db")
	if e != nil || report.WALBytes != 0 {
		t.Fatal(report, e)
	}
}
