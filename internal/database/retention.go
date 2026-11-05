package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const DefaultRetentionDays = 30
const DefaultUnknownRetentionDays = 90
const MaxPruneBatch = 1000

type PruneItem struct {
	TaskID     string              `json:"task_id"`
	NodeID     string              `json:"node_id"`
	Status     protocol.TaskStatus `json:"status"`
	HasResult  bool                `json:"has_result"`
	RetainedAt int64               `json:"retained_at"`
}

type PruneReport struct {
	RetainDays    int         `json:"retain_days"`
	UnknownDays   int         `json:"unknown_days"`
	Cutoff        int64       `json:"cutoff"`
	UnknownCutoff int64       `json:"unknown_cutoff"`
	Limit         int         `json:"limit"`
	Items         []PruneItem `json:"items"`
	Applied       bool        `json:"applied"`
	Deleted       int         `json:"deleted"`
	Backup        string      `json:"backup,omitempty"`
}

// Both retention clocks come from the server. Agent-provided completion times
// cannot shorten or indefinitely extend retention. Active work stays protected.
const pruneEligible = `((r.task_id IS NOT NULL AND t.status IN ('SUCCEEDED','FAILED','UNKNOWN')
 AND r.status=t.status AND r.node_id=t.node_id AND r.received_at<?)
 OR (r.task_id IS NULL AND t.status='UNKNOWN' AND t.result_due_at<? AND t.dispatch_expires_at<?))`

func (s *Store) PreviewPrune(ctx context.Context, retainDays, unknownDays, limit int) (PruneReport, error) {
	p := PruneReport{RetainDays: retainDays, UnknownDays: unknownDays, Limit: limit, Items: []PruneItem{}}
	if retainDays < 1 || retainDays > 36500 || unknownDays < 1 || unknownDays > 36500 || limit < 1 || limit > MaxPruneBatch {
		return p, errors.New("retention must be 1-36500 days and batch limit 1-1000")
	}
	now := s.now()
	p.Cutoff = now.Add(-time.Duration(retainDays) * 24 * time.Hour).Unix()
	p.UnknownCutoff = now.Add(-time.Duration(unknownDays) * 24 * time.Hour).Unix()
	rows, err := s.DB.QueryContext(ctx, `SELECT t.id,t.node_id,t.status,r.task_id IS NOT NULL,
 coalesce(r.received_at,max(t.result_due_at,t.dispatch_expires_at)) AS retained_at
 FROM tasks t LEFT JOIN results r ON r.task_id=t.id WHERE `+pruneEligible+`
 ORDER BY retained_at,t.id LIMIT ?`, p.Cutoff, p.UnknownCutoff, p.UnknownCutoff, limit)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var item PruneItem
		if err = rows.Scan(&item.TaskID, &item.NodeID, &item.Status, &item.HasResult, &item.RetainedAt); err != nil {
			return p, err
		}
		p.Items = append(p.Items, item)
	}
	return p, rows.Err()
}

// Prune freezes a bounded candidate list before making the verified backup.
// Newly arriving results cannot enter that batch after its snapshot is taken.
// Audit and both row deletions commit together; any stale candidate aborts all.
func (s *Store) Prune(ctx context.Context, retainDays, unknownDays, limit int, backup string) (PruneReport, error) {
	p, err := s.PreviewPrune(ctx, retainDays, unknownDays, limit)
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
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM tasks t LEFT JOIN results r ON r.task_id=t.id
 WHERE t.id=? AND t.node_id=? AND t.status=? AND (r.task_id IS NOT NULL)=?
 AND coalesce(r.received_at,max(t.result_due_at,t.dispatch_expires_at))=? AND `+pruneEligible,
			item.TaskID, item.NodeID, item.Status, item.HasResult, item.RetainedAt, p.Cutoff, p.UnknownCutoff, p.UnknownCutoff).Scan(&count)
		if err != nil {
			return err
		}
		if count != 1 {
			return errors.New("prune candidates changed; inspect state and preview again")
		}
		if err = Audit(ctx, tx, "local-operator", "task.prune", item.NodeID, item.TaskID, string(item.Status)); err != nil {
			return err
		}
		if item.HasResult {
			if err = updateOne(ctx, tx, "DELETE FROM results WHERE task_id=?", item.TaskID); err != nil {
				return err
			}
		}
		if err = updateOne(ctx, tx, "DELETE FROM tasks WHERE id=? AND node_id=? AND status=?", item.TaskID, item.NodeID, item.Status); err != nil {
			return err
		}
	}
	return nil
}
