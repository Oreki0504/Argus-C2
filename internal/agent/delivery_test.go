package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"modernc.org/sqlite"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestDiscardKeepsDeduplicationAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, e := OpenState(dir, "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { s.Close() }()
	calls := 0
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls++
		return goodPayload(), nil
	}}
	job := task("discard")
	if _, e = engine.Process(t.Context(), job, start); e != nil {
		t.Fatal(e)
	}
	before, e := s.ResultBytes(t.Context(), job.ID)
	if e != nil || len(before) == 0 {
		t.Fatal(e)
	}
	if e = s.Hold(t.Context(), job.ID, "result_conflict"); e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Process(t.Context(), job, start); !errors.Is(e, ErrResultHeld) {
		t.Fatal(e)
	}
	if e = s.Retry(t.Context(), job.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Discard(t.Context(), job.ID); e != nil {
		t.Fatal(e)
	}
	for _, reopen := range []bool{false, true} {
		if reopen {
			s.Close()
			s, e = OpenState(dir, "node", false)
			if e != nil {
				t.Fatal(e)
			}
			engine.State = s
		}
		if _, e = engine.Process(t.Context(), job, start); !errors.Is(e, ErrResultDiscarded) {
			t.Fatal(e)
		}
		if calls != 1 {
			t.Fatal("discarded task executed again", calls)
		}
		if _, e = s.ResultBytes(t.Context(), job.ID); !errors.Is(e, ErrResultDiscarded) {
			t.Fatal(e)
		}
		if e = s.Retry(t.Context(), job.ID); e == nil {
			t.Fatal("discarded report can retry")
		}
		if e = s.Acknowledge(t.Context(), job.ID); e == nil {
			t.Fatal("discard mistaken for acknowledgment")
		}
		record, e := s.Delivery(t.Context(), job.ID)
		if e != nil || record.Delivery != "discarded" || record.Status != protocol.Succeeded || record.Bytes != 0 {
			t.Fatal(record, e)
		}
		var assigned string
		if e = s.db.QueryRow("SELECT task FROM executions WHERE id=?", job.ID).Scan(&assigned); e != nil || assigned == "" {
			t.Fatal("assignment lost", e)
		}
	}
}

func TestDiscardTransactionFailureRetainsOriginal(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	job := task("retain")
	if _, e = s.prepare(t.Context(), job); e != nil {
		t.Fatal(e)
	}
	if e = s.finish(t.Context(), protocol.NewResult(job, protocol.Failed, "denied")); e != nil {
		t.Fatal(e)
	}
	before, _ := s.ResultBytes(t.Context(), job.ID)
	if _, e = s.db.Exec("CREATE TRIGGER no_discard BEFORE UPDATE OF delivery ON executions WHEN NEW.delivery='discarded' BEGIN SELECT RAISE(FAIL,'failure'); END"); e != nil {
		t.Fatal(e)
	}
	if e = s.Discard(t.Context(), job.ID); e == nil {
		t.Fatal("failure hidden")
	}
	after, e := s.ResultBytes(t.Context(), job.ID)
	if e != nil || string(after) != string(before) {
		t.Fatal("partial deletion", e)
	}
}

func TestCapacityCountsUTF8AndReservations(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	// A single unfinished execution reserves the full maximum before any report exists.
	if _, e = s.prepare(t.Context(), task("reserved")); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 511; i++ {
		// Synthetic held bodies exercise byte accounting without collecting enormous reports.
		raw := strings.Repeat("界", protocol.MaxResultBytes/3)
		if _, e = s.db.Exec("INSERT INTO executions(id,task,status,result,delivery,dispatch_expires_at) VALUES(?,'{}','FAILED',?,'held',1)", fmt.Sprint("held-", i), raw); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.prepare(t.Context(), task("overflow")); !errors.Is(e, ErrCapacity) {
		t.Fatal("UTF8/reservation undercount", e)
	}
	if _, e = s.db.Exec("DELETE FROM executions WHERE id='held-0'"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.prepare(t.Context(), task("fits")); e != nil {
		t.Fatal("capacity was not released", e)
	}
}

func TestCapacityCountAndAtomicAcceptance(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	tx, e := s.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 999; i++ {
		if _, e = tx.Exec("INSERT INTO executions(id,task,status,result,delivery,dispatch_expires_at) VALUES(?,'{}','FAILED','{}','held',1)", fmt.Sprint(i)); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.prepare(t.Context(), task("last")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.prepare(t.Context(), task("over")); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	var count int
	if e = s.db.QueryRow("SELECT count(*) FROM executions WHERE id='over'").Scan(&count); e != nil || count != 0 {
		t.Fatal("accepted without capacity", e)
	}
}

func TestSQLiteFullBeforeAcceptanceNeverCollects(t *testing.T) {
	s, e := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	// SQLite's actual SQLITE_FULL path, distinct from trigger-injected errors.
	if _, e = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		t.Fatal(e)
	}
	var pages int
	if e = s.db.QueryRow("PRAGMA page_count").Scan(&pages); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); e != nil {
		t.Fatal(e)
	}
	calls := 0
	engine := Engine{State: s, Policy: policy.Default(), Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls++
		return goodPayload(), nil
	}}
	var failure error
	for i := 0; i < 100; i++ {
		before := calls
		_, failure = engine.Process(t.Context(), task(fmt.Sprint("full-", i)), start)
		if failure != nil {
			if calls != before {
				t.Fatal("collection started without durable acceptance")
			}
			break
		}
	}
	var sqliteError *sqlite.Error
	if !errors.As(failure, &sqliteError) || sqliteError.Code() != 13 {
		t.Fatal("did not exercise SQLite full", failure)
	}
	if _, e = s.db.Exec("PRAGMA max_page_count=10000"); e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Process(t.Context(), task("space-restored"), start); e != nil {
		t.Fatal("did not recover", e)
	}
}
