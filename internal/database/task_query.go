package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type TaskQuery struct {
	NodeID                      string
	Status                      protocol.TaskStatus
	CreatedAfter, CreatedBefore int64
	Limit                       int
	Cursor                      string
}
type TaskPage struct {
	Items      []protocol.Task `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}
type taskCursor struct {
	CreatedAt int64               `json:"created_at"`
	ID        string              `json:"id"`
	NodeID    string              `json:"node_id"`
	Status    protocol.TaskStatus `json:"status"`
	After     int64               `json:"created_after"`
	Before    int64               `json:"created_before"`
}

func (q TaskQuery) cursor() (taskCursor, error) {
	var c taskCursor
	if q.Limit < 1 || q.Limit > 200 || q.NodeID != "" && !identity.Valid(q.NodeID) || q.CreatedAfter < 0 || q.CreatedBefore < 0 || q.CreatedBefore > 0 && q.CreatedBefore < q.CreatedAfter {
		return c, errors.New("invalid task query bounds")
	}
	switch q.Status {
	case "", protocol.Pending, protocol.Accepted, protocol.Running, protocol.Succeeded, protocol.Failed, protocol.Unknown:
	default:
		return c, errors.New("invalid task status filter")
	}
	if q.Cursor == "" {
		return c, nil
	}
	if len(q.Cursor) > 2048 {
		return c, errors.New("task cursor too large")
	}
	b, err := base64.RawURLEncoding.DecodeString(q.Cursor)
	if err != nil {
		return c, errors.New("invalid task cursor")
	}
	if err = strictjson.Decode(b, &c, 1024, "created_at", "id", "node_id", "status", "created_after", "created_before"); err != nil {
		return c, errors.New("invalid task cursor")
	}
	if c.CreatedAt <= 0 || !identity.Valid(c.ID) || c.NodeID != q.NodeID || c.Status != q.Status || c.After != q.CreatedAfter || c.Before != q.CreatedBefore {
		return c, errors.New("task cursor does not match filters")
	}
	return c, nil
}

func (q TaskQuery) Validate() error { _, err := q.cursor(); return err }

// QueryTasks uses a stable keyset instead of offsets or random-ID chronology.
// It is a live listing: status changes between pages are not a snapshot.
func (s *Store) QueryTasks(ctx context.Context, q TaskQuery) (TaskPage, error) {
	p := TaskPage{Items: []protocol.Task{}}
	c, err := q.cursor()
	if err != nil {
		return p, err
	}
	conditions := []string{"1=1"}
	args := []any{}
	if q.NodeID != "" {
		conditions = append(conditions, "node_id=?")
		args = append(args, q.NodeID)
	}
	if q.Status != "" {
		conditions = append(conditions, "status=?")
		args = append(args, q.Status)
	}
	if q.CreatedAfter > 0 {
		conditions = append(conditions, "created_at>=?")
		args = append(args, q.CreatedAfter)
	}
	if q.CreatedBefore > 0 {
		conditions = append(conditions, "created_at<=?")
		args = append(args, q.CreatedBefore)
	}
	if q.Cursor != "" {
		conditions = append(conditions, "(created_at,id)<(?,?)")
		args = append(args, c.CreatedAt, c.ID)
	}
	args = append(args, q.Limit+1)
	err = s.Write(ctx, func(tx *sql.Tx) error {
		if err := expire(ctx, tx, s.now().Unix()); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE "+strings.Join(conditions, " AND ")+" ORDER BY created_at DESC,id DESC LIMIT ?", args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			task, err := scanTask(rows)
			if err != nil {
				return err
			}
			p.Items = append(p.Items, task)
		}
		return rows.Err()
	})
	if err != nil {
		return p, err
	}
	if len(p.Items) > q.Limit {
		p.Items = p.Items[:q.Limit]
		last := p.Items[len(p.Items)-1]
		b, _ := json.Marshal(taskCursor{CreatedAt: last.CreatedAt, ID: last.ID, NodeID: q.NodeID, Status: q.Status, After: q.CreatedAfter, Before: q.CreatedBefore})
		p.NextCursor = base64.RawURLEncoding.EncodeToString(b)
	}
	return p, nil
}
