package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const DefaultRetentionDays = 30
const MaxPruneBatch = 1000

type PruneItem struct {
	TaskID string              `json:"task_id"`
	NodeID string              `json:"node_id"`
	Status protocol.TaskStatus `json:"status"`
}

type PruneReport struct {
	RetainDays int         `json:"retain_days"`
	Cutoff     int64       `json:"cutoff"`
	Limit      int         `json:"limit"`
	Items      []PruneItem `json:"items"`
	Applied    bool        `json:"applied"`
	Deleted    int         `json:"deleted"`
	Backup     string      `json:"backup,omitempty"`
}

// Retention is based on server-issued task deadlines, not an untrusted claim
// about receipt time. A later agent completion timestamp can only defer pruning.
// Inferred UNKNOWN and active work are always retained.
const pruneEligible = `t.status IN ('SUCCEEDED','FAILED','UNKNOWN')
 AND r.status=t.status AND r.node_id=t.node_id
 AND t.dispatch_expires_at<? AND t.result_due_at<? AND r.completed_at<?`

func (s *Store) PreviewPrune(ctx context.Context, retainDays, limit int) (PruneReport, error) {
	p := PruneReport{RetainDays: retainDays, Limit: limit, Items: []PruneItem{}}
	if retainDays < 1 || retainDays > 36500 || limit < 1 || limit > MaxPruneBatch {
		return p, errors.New("retention must be 1-36500 days and batch limit 1-1000")
	}
	p.Cutoff = s.now().Add(-time.Duration(retainDays) * 24 * time.Hour).Unix()
	rows, err := s.DB.QueryContext(ctx, `SELECT t.id,t.node_id,t.status
 FROM tasks t JOIN results r ON r.task_id=t.id WHERE `+pruneEligible+`
 ORDER BY t.result_due_at,t.id LIMIT ?`, p.Cutoff, p.Cutoff, p.Cutoff, limit)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var item PruneItem
		if err = rows.Scan(&item.TaskID, &item.NodeID, &item.Status); err != nil {
			return p, err
		}
		p.Items = append(p.Items, item)
	}
	return p, rows.Err()
}

// Prune freezes a bounded candidate list before making the verified backup.
// Newly arriving results cannot enter that batch after its snapshot is taken.
// Audit and both row deletions commit together; any stale candidate aborts all.
func (s *Store) Prune(ctx context.Context, retainDays, limit int, backup string) (PruneReport, error) {
	p, err := s.PreviewPrune(ctx, retainDays, limit)
	if err != nil {
		return p, err
	}
	if backup == "" {
		return p, errors.New("a new backup path is required before pruning")
	}
	if err = s.Backup(ctx, backup); err != nil {
		return p, err
	}
	p.Backup = backup
	err = s.Write(ctx, func(tx *sql.Tx) error { return pruneBatch(ctx, tx, p) })
	if err == nil {
		p.Applied, p.Deleted = true, len(p.Items)
	}
	return p, err
}

func pruneBatch(ctx context.Context, tx *sql.Tx, p PruneReport) error {
	for _, item := range p.Items {
		var count int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM tasks t JOIN results r ON r.task_id=t.id
 WHERE t.id=? AND t.node_id=? AND t.status=? AND `+pruneEligible,
			item.TaskID, item.NodeID, item.Status, p.Cutoff, p.Cutoff, p.Cutoff).Scan(&count)
		if err != nil {
			return err
		}
		if count != 1 {
			return errors.New("prune candidates changed; inspect state and preview again")
		}
		if err = Audit(ctx, tx, "local-operator", "task.prune", item.NodeID, item.TaskID, string(item.Status)); err != nil {
			return err
		}
		if err = updateOne(ctx, tx, "DELETE FROM results WHERE task_id=?", item.TaskID); err != nil {
			return err
		}
		if err = updateOne(ctx, tx, "DELETE FROM tasks WHERE id=? AND node_id=? AND status=?", item.TaskID, item.NodeID, item.Status); err != nil {
			return err
		}
	}
	return nil
}
