package audit

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/localdb"
)

func database(t *testing.T) *sql.DB {
	t.Helper()
	db, err := localdb.Open(filepath.Join(t.TempDir(), "state"), "probe.db", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := Initialize(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := Append(t.Context(), tx, Event{Kind: "test", Source: "local", Status: "succeeded"}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return db
}
func TestDetectsTamperingAndAuditsReads(t *testing.T) {
	for _, query := range []string{"DELETE FROM audit_events WHERE sequence=2", "DELETE FROM audit_events WHERE sequence=3", "UPDATE audit_events SET kind='changed' WHERE sequence=1", "UPDATE audit_events SET event='{}' WHERE sequence=1", "UPDATE audit_head SET hash='bad'", "UPDATE audit_head SET reserved=-1"} {
		t.Run(query, func(t *testing.T) {
			db := database(t)
			if _, err := db.Exec(query); err != nil {
				if query == "UPDATE audit_head SET reserved=-1" {
					return
				}
				t.Fatal(err)
			}
			tx, err := db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := Verify(t.Context(), tx); err == nil {
				t.Fatal("tampering undetected")
			}
		})
	}
	db := database(t)
	page, err := Read(t.Context(), db, 1, 1)
	if err != nil || len(page.Records) != 1 || page.Records[0].Sequence != 2 || page.HeadSequence != 4 {
		t.Fatal(page, err)
	}
	if _, err := Read(t.Context(), db, 0, 201); err == nil {
		t.Fatal("unbounded audit query")
	}
	page, err = Read(t.Context(), db, 3, 100)
	if err != nil || page.Records[0].Event.Kind != "audit_read" {
		t.Fatal("read not audited", err)
	}
}
func TestReservedCompletionSlotCannotBeConsumedByRead(t *testing.T) {
	db := database(t)
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Exercise boundary accounting without generating 100,000 events. Full-chain
	// verification is tested separately; this fixture intentionally has a gap.
	if _, err := tx.Exec("UPDATE audit_events SET sequence=? WHERE sequence=3", Capacity-1); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("UPDATE audit_head SET sequence=?,reserved=1", Capacity-1); err != nil {
		t.Fatal(err)
	}
	e := Event{Kind: "read", Source: "local", Status: "succeeded"}
	if err := Append(t.Context(), tx, e, 0); !errors.Is(err, ErrCapacity) {
		t.Fatal("read stole completion capacity", err)
	}
	e.Kind = "completed"
	if err := Append(t.Context(), tx, e, -1); err != nil {
		t.Fatal("reserved completion failed", err)
	}
	if err := Append(t.Context(), tx, e, -1); err == nil {
		t.Fatal("double-spent reservation")
	}
}
