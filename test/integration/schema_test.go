package integration

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/localdb"
)

func TestIncompatibleStateIsPreserved(t *testing.T) {
	for _, component := range []string{"server", "agent"} {
		for _, mismatch := range []string{"schema", "component", "empty_component"} {
			t.Run(component+"/"+mismatch, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "state")
				name, version, application := "argus.db", database.SchemaVersion, 0x41524753
				if component == "agent" {
					name, version, application = "probe.db", agent.SchemaVersion, 0x41524741
				}
				if mismatch == "schema" {
					version++
				} else if component == "server" {
					application = 0x41524741
				} else {
					application = 0x41524753
				}
				if mismatch == "empty_component" {
					version = 0
				}
				db, err := localdb.Open(dir, name, true)
				if err != nil {
					t.Fatal(err)
				}
				marker := "CREATE TABLE preserved(value TEXT); INSERT INTO preserved VALUES('keep');"
				if mismatch == "empty_component" {
					marker = ""
				}
				_, err = db.Exec(fmt.Sprintf("%s PRAGMA user_version=%d; PRAGMA application_id=%d", marker, version, application))
				if err != nil {
					t.Fatal(err)
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
				for _, create := range []bool{false, true} {
					if component == "server" {
						s, err := database.Open(dir, create)
						if err == nil {
							s.Close()
							t.Fatal("incompatible server state accepted")
						}
					} else {
						s, err := agent.OpenState(dir, "node", create)
						if err == nil {
							s.Close()
							t.Fatal("incompatible agent state accepted")
						}
					}
				}
				db, err = localdb.Open(dir, name, false)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var value string
				var actualVersion, actualApplication int
				if mismatch == "empty_component" {
					var count int
					if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count); err != nil || count != 0 {
						t.Fatal("foreign empty database initialized", count, err)
					}
				} else if err = db.QueryRow("SELECT value FROM preserved").Scan(&value); err != nil || value != "keep" {
					t.Fatal("incompatible state modified", value, err)
				}
				if err = db.QueryRow("PRAGMA user_version").Scan(&actualVersion); err != nil || actualVersion != version {
					t.Fatal("schema reset", actualVersion, err)
				}
				if err = db.QueryRow("PRAGMA application_id").Scan(&actualApplication); err != nil || actualApplication != application {
					t.Fatal("component reset", actualApplication, err)
				}
			})
		}
	}
}
