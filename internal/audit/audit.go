// Package audit appends bounded hash-chained events in the same transaction as
// security state. It does not claim protection against whole-database rewriting.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const Capacity = 100000

var ErrCapacity = errors.New("audit capacity exhausted; new operations are paused")
var genesis = strings.Repeat("0", 64)

type Event struct {
	At            int64             `json:"at_unix_nano"`
	Kind          string            `json:"kind"`
	AgentID       string            `json:"agent_id"`
	Epoch         string            `json:"epoch"`
	RequestID     string            `json:"request_id"`
	TaskType      protocol.TaskType `json:"task_type"`
	ActorID       string            `json:"actor_id"`
	Source        string            `json:"source"`
	Status        string            `json:"status"`
	Code          string            `json:"code"`
	PolicyDigest  string            `json:"policy_digest"`
	PayloadDigest string            `json:"payload_digest"`
	ResultDigest  string            `json:"result_digest"`
}
type Record struct {
	Sequence int64  `json:"sequence"`
	Event    Event  `json:"event"`
	Previous string `json:"previous_hash"`
	Hash     string `json:"hash"`
}
type Page struct {
	Records      []Record `json:"records"`
	HeadSequence int64    `json:"head_sequence"`
	HeadHash     string   `json:"head_hash"`
}

func Initialize(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `CREATE TABLE audit_head(id INTEGER PRIMARY KEY CHECK(id=1),sequence INTEGER NOT NULL,hash TEXT NOT NULL,reserved INTEGER NOT NULL CHECK(reserved>=0));
INSERT INTO audit_head VALUES(1,0,?,0);
CREATE TABLE audit_events(sequence INTEGER PRIMARY KEY,event BLOB NOT NULL,previous_hash TEXT NOT NULL,hash TEXT NOT NULL,kind TEXT NOT NULL,agent_id TEXT NOT NULL,request_id TEXT NOT NULL);
CREATE UNIQUE INDEX audit_execution_decision ON audit_events(agent_id,request_id) WHERE kind IN ('task_accepted','task_rejected');`, genesis)
	return err
}

func identifier(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func (e Event) validate() error {
	if e.At <= 0 || !identifier(e.Kind, 40) || e.Kind == "" || !identifier(e.ActorID, 64) || !identifier(e.Status, 32) || !identifier(e.Code, 64) || !protocol.CleanText(e.Source, 256) {
		return errors.New("invalid audit event")
	}
	for _, v := range []string{e.AgentID, e.Epoch, e.RequestID} {
		if v != "" && !identity.Hex(v, 32) {
			return errors.New("invalid audit identity")
		}
	}
	for _, v := range []string{e.PolicyDigest, e.PayloadDigest, e.ResultDigest} {
		if v != "" && !identity.Hex(v, 64) {
			return errors.New("invalid audit digest")
		}
	}
	if e.TaskType != "" && !protocol.KnownTask(e.TaskType) {
		return errors.New("invalid audited task")
	}
	return nil
}
func Digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func chain(previous string, data []byte) string {
	return Digest(append([]byte("argus-c2/audit/v1\x00"+previous+"\x00"), data...))
}

// reserveDelta reserves completion slots before work starts, or consumes them
// when it finishes. Ordinary appends cannot consume another task's reservation.
func Append(ctx context.Context, tx *sql.Tx, e Event, reserveDelta int) error {
	if e.At == 0 {
		e.At = time.Now().UnixNano()
	}
	if err := e.validate(); err != nil {
		return err
	}
	var seq int64
	var head string
	var reserved int
	if err := tx.QueryRowContext(ctx, "SELECT sequence,hash,reserved FROM audit_head WHERE id=1").Scan(&seq, &head, &reserved); err != nil {
		return err
	}
	if seq < 0 || !identity.Hex(head, 64) || reserved+reserveDelta < 0 {
		return errors.New("invalid audit head or reservation")
	}
	if seq+1+int64(reserved+reserveDelta) > Capacity {
		return ErrCapacity
	}
	if seq > 0 {
		var actual string
		if err := tx.QueryRowContext(ctx, "SELECT hash FROM audit_events WHERE sequence=?", seq).Scan(&actual); err != nil || actual != head {
			return errors.New("audit head mismatch")
		}
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	hash := chain(head, data)
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events VALUES(?,?,?,?,?,?,?)", seq+1, data, head, hash, e.Kind, e.AgentID, e.RequestID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE audit_head SET sequence=?,hash=?,reserved=? WHERE id=1", seq+1, hash, reserved+reserveDelta)
	return err
}

func Verify(ctx context.Context, tx *sql.Tx) error {
	var sequence int64
	var head string
	var reserved int
	if err := tx.QueryRowContext(ctx, "SELECT sequence,hash,reserved FROM audit_head WHERE id=1").Scan(&sequence, &head, &reserved); err != nil {
		return err
	}
	if sequence < 0 || sequence+int64(reserved) > Capacity || reserved < 0 {
		return errors.New("invalid audit capacity state")
	}
	rows, err := tx.QueryContext(ctx, "SELECT sequence,event,previous_hash,hash,kind,agent_id,request_id FROM audit_events ORDER BY sequence LIMIT ?", Capacity+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := int64(0)
	previous := genesis
	for rows.Next() {
		var seq int64
		var data []byte
		var prev, hash, kind, node, request string
		if err := rows.Scan(&seq, &data, &prev, &hash, &kind, &node, &request); err != nil {
			return err
		}
		var e Event
		if err := decode(data, &e); err != nil {
			return err
		}
		n++
		if seq != n || prev != previous || hash != chain(prev, data) || kind != e.Kind || node != e.AgentID || request != e.RequestID {
			return errors.New("audit chain verification failed")
		}
		previous = hash
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if n != sequence || previous != head {
		return errors.New("audit tail is missing or inconsistent")
	}
	return nil
}
func decode(data []byte, e *Event) error {
	if err := strictjson.Decode(data, e, 2048, "at_unix_nano", "kind", "agent_id", "epoch", "request_id", "task_type", "actor_id", "source", "status", "code", "policy_digest", "payload_digest", "result_digest"); err != nil {
		return err
	}
	return e.validate()
}
func Read(ctx context.Context, db *sql.DB, after int64, limit int) (Page, error) {
	if after < 0 || limit < 1 || limit > 200 {
		return Page{}, errors.New("invalid audit page")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Page{}, err
	}
	defer tx.Rollback()
	p, err := ReadTx(ctx, tx, after, limit, "local-operator", "local")
	if err != nil {
		return Page{}, err
	}
	return p, tx.Commit()
}

// ReadTx lets management bind live authorization and access auditing to the
// same transaction as the returned page. It never commits the caller's work.
func ReadTx(ctx context.Context, tx *sql.Tx, after int64, limit int, actor, source string) (Page, error) {
	if after < 0 || limit < 1 || limit > 200 {
		return Page{}, errors.New("invalid audit page")
	}
	if err := Verify(ctx, tx); err != nil {
		return Page{}, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT sequence,event,previous_hash,hash FROM audit_events WHERE sequence>? ORDER BY sequence LIMIT ?", after, limit)
	if err != nil {
		return Page{}, err
	}
	p := Page{Records: []Record{}}
	for rows.Next() {
		var r Record
		var data []byte
		if err := rows.Scan(&r.Sequence, &data, &r.Previous, &r.Hash); err != nil {
			rows.Close()
			return Page{}, err
		}
		if err := decode(data, &r.Event); err != nil {
			rows.Close()
			return Page{}, err
		}
		p.Records = append(p.Records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Page{}, err
	}
	if err := Append(ctx, tx, Event{Kind: "audit_read", ActorID: actor, Source: source, Status: "succeeded", Code: "after_" + strconv.FormatInt(after, 10) + "_limit_" + strconv.Itoa(limit)}, 0); err != nil {
		return Page{}, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT sequence,hash FROM audit_head WHERE id=1").Scan(&p.HeadSequence, &p.HeadHash); err != nil {
		return Page{}, err
	}
	return p, nil
}
func Peer(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil || net.ParseIP(host) == nil {
		return "unknown"
	}
	return host
}
func TaskEvent(kind string, t protocol.Task, source, status, code, digest string) Event {
	return Event{Kind: kind, AgentID: t.AgentID, Epoch: t.EnrollmentEpoch, RequestID: t.RequestID, TaskType: t.Type, ActorID: t.ActorID, Source: source, Status: status, Code: code, PolicyDigest: t.PolicyDigest, PayloadDigest: digest}
}
