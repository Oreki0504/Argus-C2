package state

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

var ErrManagementRequest = errors.New("invalid management request")
var ErrManagementConflict = errors.New("management operation could not be completed")
var ErrManagementNotFound = errors.New("management record not found")

type ManagementRequest struct {
	Operation  string
	AgentID    string
	RequestID  string
	AfterNode  string
	After      int64
	Limit      int
	Type       protocol.TaskType
	Params     json.RawMessage
	TTLSeconds int
}

func pageScope(after, id string, limit int) string {
	if id != "" {
		return "id_" + id
	}
	if after == "" {
		after = "start"
	}
	return "after_" + after + "_limit_" + strconv.Itoa(limit)
}
func (r ManagementRequest) validate() error {
	if r.After < 0 || r.Limit < 0 || r.Limit > 50 || (r.AgentID != "" && !identity.Hex(r.AgentID, 32)) || (r.RequestID != "" && !identity.Hex(r.RequestID, 32)) || (r.AfterNode != "" && !identity.Hex(r.AfterNode, 32)) {
		return ErrManagementRequest
	}
	switch r.Operation {
	case "agents":
		if r.Limit < 1 || r.After != 0 || r.RequestID != "" {
			return ErrManagementRequest
		}
	case "tasks":
		if r.Limit < 1 || r.AfterNode != "" || r.AgentID != "" {
			return ErrManagementRequest
		}
	case "audit":
		if r.Limit < 1 || r.AfterNode != "" || r.AgentID != "" || r.RequestID != "" {
			return ErrManagementRequest
		}
	case "submit":
		t := protocol.Task{Version: 1, RequestID: identity.RandomID(), AgentID: r.AgentID, EnrollmentEpoch: identity.RandomID(), CreatedAt: 1, ExpiresAt: 1 + int64(r.TTLSeconds), Type: r.Type, TaskVersion: 1, Params: r.Params, ActorID: "validation", PolicyDigest: audit.Digest(nil)}
		if t.Validate() != nil {
			return ErrManagementRequest
		}
	case "token":
		if r.TTLSeconds < 1 || r.TTLSeconds > 900 {
			return ErrManagementRequest
		}
	case "disable":
		if r.AgentID == "" {
			return ErrManagementRequest
		}
	case "whoami", "logout", "revoke":
	default:
		return ErrManagementRequest
	}
	if r.Operation != "submit" && (r.Type != "" || len(r.Params) != 0) {
		return ErrManagementRequest
	}
	if r.Operation != "submit" && r.Operation != "token" && r.TTLSeconds != 0 {
		return ErrManagementRequest
	}
	return nil
}

// Manage is the sole network administration entry into storage. The session is
// resolved from an opaque token inside the same immediate transaction as role
// checking, the operation, session activity, and its audit record.
func (s *Store) Manage(ctx context.Context, token, source string, r ManagementRequest) (any, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if err := adminClock(ctx, tx, now); err != nil {
		return nil, err
	}
	if err := expireSessionsTx(ctx, tx, now); err != nil {
		return nil, err
	}
	current, err := authorizeAdminTx(ctx, tx, token, now)
	if err != nil {
		// Invalid credentials are shed by the handler's bounded request budget; do
		// not let unauthenticated traffic fill the durable audit log indefinitely.
		if errors.Is(err, ErrAdminUnauthorized) {
			if e := tx.Commit(); e != nil {
				return nil, e
			}
		}
		return nil, err
	}
	actor := current.User.ID
	privileged := r.Operation == "submit" || r.Operation == "token" || r.Operation == "disable"
	if privileged && current.User.Role != adminauth.Admin {
		if err := audit.Append(ctx, tx, audit.Event{Kind: "admin_denied", ActorID: actor, Source: source, Status: "rejected", Code: r.Operation}, 0); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrAdminForbidden
	}
	var result any = struct {
		OK bool `json:"ok"`
	}{true}
	// Roll back partial domain work before recording a rejected operation.
	// Authorization, expiry housekeeping, and the rejection audit stay atomic.
	if _, err := tx.ExecContext(ctx, "SAVEPOINT management_operation"); err != nil {
		return nil, err
	}
	switch r.Operation {
	case "whoami":
		result = current.User
		err = audit.Append(ctx, tx, audit.Event{Kind: "session_read", ActorID: actor, Source: source, Status: "succeeded"}, 0)
	case "logout":
		err = revokeSessionTx(ctx, tx, current.ID, actor, actor, source, "session_logout")
	case "revoke":
		err = revokeUserSessionsTx(ctx, tx, actor, actor, source)
		if err == nil {
			_, err = tx.ExecContext(ctx, "UPDATE admin_users SET generation=generation+1 WHERE id=?", actor)
		}
	case "agents":
		var rows []Snapshot
		rows, err = snapshotsTx(ctx, tx, r.AfterNode, r.AgentID, r.Limit, actor, source)
		result = rows
		if err == nil && r.AgentID != "" {
			if len(rows) == 0 {
				err = ErrManagementNotFound
			} else {
				result = rows[0]
			}
		}
	case "tasks":
		var rows []TaskRecord
		rows, err = tasksTx(ctx, tx, r.After, r.Limit, r.RequestID, actor, source)
		result = rows
		if err == nil && r.RequestID != "" {
			if len(rows) == 0 {
				err = ErrManagementNotFound
			} else {
				result = rows[0]
			}
		}
	case "audit":
		result, err = audit.ReadTx(ctx, tx, r.After, r.Limit, actor, source)
	case "submit":
		result, err = enqueueTx(ctx, tx, r.AgentID, r.Type, actor, source, time.Duration(r.TTLSeconds)*time.Second, r.Params)
	case "token":
		var value string
		value, err = issueTokenTx(ctx, tx, time.Duration(r.TTLSeconds)*time.Second, actor, source)
		var expires int64
		if err == nil {
			hash, _ := tokenHash(value)
			err = tx.QueryRowContext(ctx, "SELECT expires_at FROM enrollment_tokens WHERE token_hash=?", hash).Scan(&expires)
		}
		result = struct {
			Token     string `json:"token"`
			ExpiresAt int64  `json:"expires_at"`
		}{value, expires}
	case "disable":
		err = disableTx(ctx, tx, r.AgentID, actor, source)
	}
	if err != nil {
		if _, rollbackErr := tx.ExecContext(ctx, "ROLLBACK TO management_operation"); rollbackErr != nil {
			return nil, rollbackErr
		}
		if errors.Is(err, audit.ErrCapacity) {
			return nil, err
		}
		if e := audit.Append(ctx, tx, audit.Event{Kind: "admin_rejected", ActorID: actor, Source: source, Status: "rejected", Code: r.Operation}, 0); e != nil {
			return nil, e
		}
		if e := tx.Commit(); e != nil {
			return nil, e
		}
		if errors.Is(err, ErrManagementNotFound) {
			return nil, err
		}
		return nil, ErrManagementConflict
	}
	if _, err := tx.ExecContext(ctx, "UPDATE admin_sessions SET last_used=MAX(last_used,?) WHERE token_hash=?", now, current.Hash); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
