package database

import (
	"context"
	"database/sql"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Oreki0504/Argus-C2/internal/identity"
)

// Display names are explicitly public labels, never inferred from hostnames.
func ValidNodeName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && utf8.ValidString(name) && utf8.RuneCountInString(name) <= 64 && strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) == -1
}

func (s *Store) RenameConsoleNode(ctx context.Context, actor, id, name string) error {
	if !identity.Valid(id) || !ValidNodeName(name) {
		return ErrConflict
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, "UPDATE console_nodes SET display_name=? WHERE node_id=?", name, id)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return Audit(ctx, tx, actor, "node.rename", id, "", "succeeded")
	})
}

// Removal and audit commit atomically. Old certificates and enrollment retries
// cannot recreate the deleted identity; reinstall requires a fresh token.
func (s *Store) DeleteConsoleNode(ctx context.Context, actor, id string) error {
	if !identity.Valid(id) {
		return ErrNotFound
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM nodes WHERE id=?", id).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return ErrNotFound
		}
		for _, table := range []string{"results", "tasks", "enrollment_tokens", "console_nodes"} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE node_id=?", id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM nodes WHERE id=?", id); err != nil {
			return err
		}
		return Audit(ctx, tx, actor, "node.delete", id, "", "succeeded")
	})
}
