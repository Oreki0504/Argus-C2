package database

import (
	"encoding/base64"
	"testing"
)

func TestTaskQueryTimeCursorAndFilters(t *testing.T) {
	s := fixture(t)
	if _, err := s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('other','host','other-fp','active',1,9999999999,'cert')"); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, node, status string
		at               int64
	}{{"z", "node", "FAILED", 10}, {"a", "node", "FAILED", 20}, {"b", "node", "FAILED", 20}, {"c", "other", "FAILED", 30}, {"d", "node", "SUCCEEDED", 40}} {
		if _, err := s.DB.Exec("INSERT INTO tasks("+taskColumns+") VALUES(?,?, 'system.info','{}',?,?,?,1000,?)", row.id, row.node, row.status, row.at, row.at+60, row.at+120); err != nil {
			t.Fatal(err)
		}
	}
	q := TaskQuery{NodeID: "node", Status: "FAILED", CreatedAfter: 10, CreatedBefore: 20, Limit: 1}
	want := []string{"b", "a", "z"}
	for i, id := range want {
		p, err := s.QueryTasks(t.Context(), q)
		if err != nil || len(p.Items) != 1 || p.Items[0].ID != id {
			t.Fatal(i, p, err)
		}
		if i == 0 {
			changed := q
			changed.NodeID = "other"
			changed.Cursor = p.NextCursor
			if _, err = s.QueryTasks(t.Context(), changed); err == nil {
				t.Fatal("cursor reused with different filter")
			}
			// Newer rows must not shift the continuation page like an offset.
			if _, err = s.DB.Exec("INSERT INTO tasks(" + taskColumns + ") VALUES('new','node','system.info','{}','FAILED',20,80,1000,140)"); err != nil {
				t.Fatal(err)
			}
		}
		q.Cursor = p.NextCursor
		if (i == len(want)-1) != (q.Cursor == "") {
			t.Fatal("incorrect continuation", i, p)
		}
	}
	for _, q := range []TaskQuery{{Limit: 0}, {Limit: 201}, {Limit: 20, Status: "healthy"}, {Limit: 20, CreatedAfter: 20, CreatedBefore: 10}, {Limit: 20, Cursor: "!"}, {Limit: 20, Cursor: base64.RawURLEncoding.EncodeToString([]byte(`{"id":"a"}`))}} {
		if _, err := s.QueryTasks(t.Context(), q); err == nil {
			t.Fatal("invalid query accepted", q)
		}
	}
}
