package console

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type managedAgent struct {
	NodeID               string `json:"node_id"`
	PublicID             string `json:"public_id"`
	DisplayName          string `json:"display_name"`
	Hostname             string `json:"hostname"`
	Status               string `json:"status"`
	LastSeenAt           int64  `json:"last_seen_at"`
	CreatedAt            int64  `json:"created_at"`
	AgentVersion         string `json:"agent_version"`
	ProtocolVersion      int    `json:"protocol_version"`
	CertificateExpiresAt int64  `json:"certificate_expires_at"`
}

const agentColumns = "n.id,p.public_id,p.display_name,n.hostname,n.status,n.last_seen_at,n.created_at,n.agent_version,n.protocol_version,n.certificate_expires_at"

func publicName(name, id string) string {
	if name != "" {
		return name
	}
	if len(id) > 8 {
		id = id[:8]
	}
	return "Server-" + id
}
func scanAgent(row scanner) (managedAgent, error) {
	var a managedAgent
	err := row.Scan(&a.NodeID, &a.PublicID, &a.DisplayName, &a.Hostname, &a.Status, &a.LastSeenAt, &a.CreatedAt, &a.AgentVersion, &a.ProtocolVersion, &a.CertificateExpiresAt)
	a.DisplayName = publicName(a.DisplayName, a.PublicID)
	return a, err
}

type scanner interface{ Scan(...any) error }
type managedTask struct {
	protocol.Task
	AgentName             string `json:"agent_name"`
	ExecutionAuthorizedAt *int64 `json:"execution_authorized_at"`
	ResultReceivedAt      *int64 `json:"result_received_at"`
}

const managedTaskColumns = "t.id,t.node_id,t.task_type,t.parameters,t.status,t.created_at,t.dispatch_expires_at,t.execution_timeout_ms,t.result_due_at,p.public_id,p.display_name,NULLIF(t.execution_authorized_at,0),r.received_at"

func scanManagedTask(row scanner) (managedTask, error) {
	var t managedTask
	var params, publicID, name string
	err := row.Scan(&t.ID, &t.NodeID, &t.Type, &params, &t.Status, &t.CreatedAt, &t.DispatchExpiresAt, &t.ExecutionTimeoutMS, &t.ResultDueAt, &publicID, &name, &t.ExecutionAuthorizedAt, &t.ResultReceivedAt)
	t.Params = json.RawMessage(params)
	t.AgentName = publicName(name, publicID)
	return t, err
}
func (s *Server) managedTask(r *http.Request, id string) (managedTask, error) {
	return scanManagedTask(s.store.DB.QueryRowContext(r.Context(), "SELECT "+managedTaskColumns+" FROM tasks t JOIN console_nodes p ON p.node_id=t.node_id LEFT JOIN results r ON r.task_id=t.id WHERE t.id=?", id))
}

type managedResult struct {
	Status      protocol.TaskStatus `json:"status"`
	Error       string              `json:"error"`
	CompletedAt int64               `json:"completed_at"`
	Payload     json.RawMessage     `json:"payload"`
}
type taskDetail struct {
	Task   managedTask    `json:"task"`
	Result *managedResult `json:"result"`
}
type auditEvent struct {
	ID        int64   `json:"id"`
	Timestamp int64   `json:"timestamp"`
	Actor     string  `json:"actor"`
	Action    string  `json:"action"`
	NodeID    *string `json:"node_id"`
	TaskID    *string `json:"task_id"`
	SubjectID *string `json:"subject_id"`
	Status    string  `json:"status"`
}
type page[T any] struct {
	Items      []T     `json:"items"`
	Total      int     `json:"total"`
	NextCursor *string `json:"next_cursor"`
}
type listCursor struct {
	Key    string `json:"key"`
	At     int64  `json:"at"`
	Filter string `json:"filter"`
}
type listSpec struct {
	from, columns, key, at string
	where                  []string
	args                   []any
}

func listParams(w http.ResponseWriter, r *http.Request, keys ...string) bool {
	allowed := map[string]bool{"cursor": true, "limit": true}
	for _, k := range keys {
		allowed[k] = true
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		problem(w, 400, "invalid_request")
		return false
	}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 || len(v[0]) > 2048 || !protocol.CleanText(v[0], 2048) {
			problem(w, 400, "invalid_request")
			return false
		}
	}
	return true
}
func searchTerm(v string) string {
	return "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(v) + "%"
}
func respondPage[T any](s *Server, w http.ResponseWriter, r *http.Request, spec listSpec, scan func(scanner) (T, error), position func(T) (string, int64)) {
	q := r.URL.Query()
	limit := 8
	if q.Get("limit") != "" {
		var err error
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 200 {
			problem(w, 400, "invalid_request")
			return
		}
	}
	q.Del("limit")
	raw := q.Get("cursor")
	q.Del("cursor")
	signature := database.TokenDigest(r.URL.Path + "?" + q.Encode())
	var cursor listCursor
	if raw != "" {
		b, err := base64.RawURLEncoding.DecodeString(raw)
		if err == nil {
			err = strictjson.Decode(b, &cursor, 1536, "key", "at", "filter")
		}
		if err != nil || !identity.Valid(cursor.Key) || cursor.At < 0 || cursor.Filter != signature {
			problem(w, 400, "invalid_request")
			return
		}
	}
	if len(spec.where) == 0 {
		spec.where = []string{"1=1"}
	}
	where := strings.Join(spec.where, " AND ")
	totalArgs := append([]any{}, spec.args...)
	order := spec.key + " DESC"
	if raw != "" {
		if spec.at != "" {
			where += " AND (" + spec.at + "," + spec.key + ")<(?,?)"
			spec.args = append(spec.args, cursor.At, cursor.Key)
		} else {
			where += " AND " + spec.key + "<?"
			spec.args = append(spec.args, cursor.Key)
		}
	}
	if spec.at != "" {
		order = spec.at + " DESC," + order
	}
	out := page[T]{Items: []T{}}
	err := s.store.Write(r.Context(), func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(r.Context(), "SELECT count(*) FROM "+spec.from+" WHERE "+strings.Join(spec.where, " AND "), totalArgs...).Scan(&out.Total); err != nil {
			return err
		}
		rows, err := tx.QueryContext(r.Context(), "SELECT "+spec.columns+" FROM "+spec.from+" WHERE "+where+" ORDER BY "+order+" LIMIT ?", append(spec.args, limit+1)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scan(rows)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		storeProblem(w, err)
		return
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		key, at := position(out.Items[limit-1])
		b, _ := json.Marshal(listCursor{key, at, signature})
		next := base64.RawURLEncoding.EncodeToString(b)
		out.NextCursor = &next
	}
	reply(w, out)
}
func (s *Server) managementRoutes(mux *http.ServeMux) {
	wrap := func(f func(http.ResponseWriter, *http.Request, database.ConsoleUser, session)) http.HandlerFunc {
		return s.authorized(true, f)
	}
	mux.HandleFunc("GET /v1/console/admin/agents", wrap(s.agents))
	mux.HandleFunc("POST /v1/console/admin/enrollment-tokens", wrap(s.enrollment))
	mux.HandleFunc("POST /v1/console/admin/agents/{id}/disable", wrap(s.disable))
	mux.HandleFunc("POST /v1/console/admin/agents/{id}/rename", wrap(s.renameAgent))
	mux.HandleFunc("POST /v1/console/admin/agents/{id}/delete", wrap(s.deleteAgent))
	mux.HandleFunc("GET /v1/console/admin/tasks", wrap(s.tasks))
	mux.HandleFunc("POST /v1/console/admin/tasks", wrap(s.createTask))
	mux.HandleFunc("GET /v1/console/admin/tasks/{id}", wrap(s.task))
	mux.HandleFunc("GET /v1/console/admin/audit", wrap(s.audit))
	mux.HandleFunc("GET /v1/console/admin/users", wrap(s.users))
	mux.HandleFunc("POST /v1/console/admin/users/{id}", wrap(s.updateUser))
	mux.HandleFunc("POST /v1/console/admin/users/{id}/revoke-sessions", wrap(s.revokeSessions))
}
func (s *Server) agents(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
	if !listParams(w, r, "q", "status", "public_id") {
		return
	}
	q := r.URL.Query()
	spec := listSpec{from: "nodes n JOIN console_nodes p ON p.node_id=n.id", columns: agentColumns, key: "n.id"}
	if search := q.Get("q"); search != "" {
		if len(search) > 128 {
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, `(n.hostname LIKE ? ESCAPE '\' OR n.id LIKE ? ESCAPE '\' OR p.display_name LIKE ? ESCAPE '\' OR ('Server-'||substr(p.public_id,1,8)) LIKE ? ESCAPE '\')`)
		term := searchTerm(search)
		spec.args = append(spec.args, term, term, term, term)
	}
	if status := q.Get("status"); status != "" {
		if status != "active" && status != "disabled" {
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, "n.status=?")
		spec.args = append(spec.args, status)
	}
	if id := q.Get("public_id"); id != "" {
		if !identity.Valid(id) {
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, "p.public_id=?")
		spec.args = append(spec.args, id)
	}
	respondPage(s, w, r, spec, scanAgent, func(a managedAgent) (string, int64) { return a.NodeID, 0 })
}
func (s *Server) enrollment(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
	var b struct {
		TTL int `json:"ttl_seconds"`
	}
	if !decode(w, r, &b, "ttl_seconds") {
		return
	}
	if b.TTL < 60 || b.TTL > 3600 {
		problem(w, 400, "invalid_request")
		return
	}
	token, err := s.store.CreateToken(r.Context(), "web:"+u.ID, time.Duration(b.TTL)*time.Second)
	if err != nil {
		storeProblem(w, err)
		return
	}
	var expires int64
	if err = s.store.DB.QueryRowContext(r.Context(), "SELECT expires_at FROM enrollment_tokens WHERE digest=?", database.TokenDigest(token)).Scan(&expires); err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, map[string]any{"token": token, "expires_at": expires})
}
func (s *Server) disable(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
	var b struct {
		Confirm string `json:"confirm_node_id"`
	}
	if !decode(w, r, &b, "confirm_node_id") {
		return
	}
	id := r.PathValue("id")
	if !identity.Valid(id) || b.Confirm != id {
		problem(w, 400, "invalid_request")
		return
	}
	if err := s.store.Disable(r.Context(), "web:"+u.ID, id); err != nil {
		storeProblem(w, err)
		return
	}
	a, err := scanAgent(s.store.DB.QueryRowContext(r.Context(), "SELECT "+agentColumns+" FROM nodes n JOIN console_nodes p ON p.node_id=n.id WHERE n.id=?", id))
	if err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, a)
}

func (s *Server) renameAgent(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
	var b struct {
		Name string `json:"display_name"`
	}
	if !decode(w, r, &b, "display_name") {
		return
	}
	id := r.PathValue("id")
	b.Name = strings.TrimSpace(b.Name)
	if !identity.Valid(id) || !database.ValidNodeName(b.Name) {
		problem(w, 400, "invalid_request")
		return
	}
	if err := s.store.RenameConsoleNode(r.Context(), "web:"+u.ID, id, b.Name); err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, struct{}{})
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, v session) {
	var b struct {
		Confirm string `json:"confirm_node_id"`
	}
	if !decode(w, r, &b, "confirm_node_id") {
		return
	}
	id := r.PathValue("id")
	if !identity.Valid(id) || b.Confirm != id {
		problem(w, 400, "invalid_request")
		return
	}
	if s.now().Sub(v.Created) > 10*time.Minute {
		problem(w, 403, "reauthentication_required")
		return
	}
	if err := s.store.DeleteConsoleNode(r.Context(), "web:"+u.ID, id); err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, struct{}{})
}
func (s *Server) tasks(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
	if !listParams(w, r, "node_id", "status", "task_type") {
		return
	}
	q := r.URL.Query()
	spec := listSpec{from: "tasks t JOIN console_nodes p ON p.node_id=t.node_id LEFT JOIN results r ON r.task_id=t.id", columns: managedTaskColumns, key: "t.id", at: "t.created_at"}
	if id := q.Get("node_id"); id != "" {
		if !identity.Valid(id) {
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, "t.node_id=?")
		spec.args = append(spec.args, id)
	}
	if kind := q.Get("task_type"); kind != "" {
		if !protocol.KnownTask(protocol.TaskType(kind)) {
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, "t.task_type=?")
		spec.args = append(spec.args, kind)
	}
	if status := q.Get("status"); status != "" {
		switch protocol.TaskStatus(status) {
		case protocol.Pending, protocol.Accepted, protocol.Running, protocol.Succeeded, protocol.Failed, protocol.Unknown:
		default:
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, "t.status=?")
		spec.args = append(spec.args, status)
	}
	if err := s.store.ExpireTasks(r.Context()); err != nil {
		storeProblem(w, err)
		return
	}
	respondPage(s, w, r, spec, scanManagedTask, func(t managedTask) (string, int64) { return t.ID, t.CreatedAt })
}
func (s *Server) createTask(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
	var b protocol.TaskRequest
	if !decode(w, r, &b, "node_id", "task_type", "parameters", "ttl_seconds", "execution_timeout_ms") {
		return
	}
	raw, err := json.Marshal(b)
	if err == nil {
		_, err = protocol.DecodeTaskRequest(raw)
	}
	if err != nil {
		problem(w, 400, "invalid_request")
		return
	}
	t, err := s.store.CreateTask(r.Context(), "web:"+u.ID, b)
	if errors.Is(err, database.ErrNodeDisabled) {
		problem(w, 409, "node_disabled")
		return
	}
	if errors.Is(err, database.ErrConflict) {
		problem(w, 409, "state_conflict")
		return
	}
	if err != nil {
		storeProblem(w, err)
		return
	}
	out, err := s.managedTask(r, t.ID)
	if err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, out)
}
func (s *Server) task(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
	id := r.PathValue("id")
	if !identity.Valid(id) {
		problem(w, 404, "not_found")
		return
	}
	view, err := s.store.Task(r.Context(), id)
	if err != nil {
		storeProblem(w, err)
		return
	}
	var publicID, name string
	if err = s.store.DB.QueryRowContext(r.Context(), "SELECT public_id,display_name FROM console_nodes WHERE node_id=?", view.Task.NodeID).Scan(&publicID, &name); err != nil {
		storeProblem(w, err)
		return
	}
	t := managedTask{Task: view.Task, AgentName: publicName(name, publicID)}
	if view.ExecutionAuthorizedAt > 0 {
		t.ExecutionAuthorizedAt = &view.ExecutionAuthorizedAt
	}
	if view.ResultReceivedAt > 0 {
		t.ResultReceivedAt = &view.ResultReceivedAt
	}
	out := taskDetail{Task: t}
	if view.Result != nil {
		v := view.Result
		out.Result = &managedResult{v.Status, v.Error, v.CompletedAt, v.Payload}
	}
	reply(w, out)
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
	if !listParams(w, r, "action", "node_id", "task_id", "subject_id") {
		return
	}
	spec := listSpec{from: "audit_events", columns: "id,timestamp,actor,action,NULLIF(node_id,''),NULLIF(task_id,''),NULLIF(subject_id,''),status", key: "id"}
	for _, k := range []string{"action", "node_id", "task_id", "subject_id"} {
		if v := r.URL.Query().Get(k); v != "" {
			if k != "action" && !identity.Valid(v) || len(v) > 128 {
				problem(w, 400, "invalid_request")
				return
			}
			spec.where = append(spec.where, k+"=?")
			spec.args = append(spec.args, v)
		}
	}
	respondPage(s, w, r, spec, func(row scanner) (auditEvent, error) {
		var a auditEvent
		err := row.Scan(&a.ID, &a.Timestamp, &a.Actor, &a.Action, &a.NodeID, &a.TaskID, &a.SubjectID, &a.Status)
		return a, err
	}, func(a auditEvent) (string, int64) { return strconv.FormatInt(a.ID, 10), 0 })
}
func (s *Server) users(w http.ResponseWriter, r *http.Request, _ database.ConsoleUser, _ session) {
	if !listParams(w, r, "q", "status") {
		return
	}
	spec := listSpec{from: "console_users", columns: "id,name,issuer,subject,role,status,created_at,last_login_at,version", key: "id"}
	q := r.URL.Query()
	if v := q.Get("q"); v != "" {
		if len(v) > 128 {
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, `(name LIKE ? ESCAPE '\' OR subject LIKE ? ESCAPE '\')`)
		spec.args = append(spec.args, searchTerm(v), searchTerm(v))
	}
	if v := q.Get("status"); v != "" {
		if v != "pending" && v != "active" && v != "disabled" {
			problem(w, 400, "invalid_request")
			return
		}
		spec.where = append(spec.where, "status=?")
		spec.args = append(spec.args, v)
	}
	respondPage(s, w, r, spec, func(row scanner) (database.ConsoleUser, error) { return database.ScanConsoleUser(row) }, func(u database.ConsoleUser) (string, int64) { return u.ID, 0 })
}
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, v session) {
	id := r.PathValue("id")
	if !identity.Valid(id) {
		problem(w, 400, "invalid_request")
		return
	}
	var b struct {
		Role    string `json:"role"`
		Status  string `json:"status"`
		Version int64  `json:"expected_version"`
		Confirm string `json:"confirm_subject"`
	}
	if !decode(w, r, &b, "role", "status", "expected_version", "confirm_subject") {
		return
	}
	if b.Role != "Admin" && b.Role != "User" || b.Status != "active" && b.Status != "disabled" || b.Version < 1 || !protocol.CleanText(b.Confirm, 255) {
		problem(w, 400, "invalid_request")
		return
	}
	target, err := s.store.ConsoleUser(r.Context(), id)
	if err != nil {
		storeProblem(w, err)
		return
	}
	if (target.Role == "Admin" || b.Role == "Admin") && s.now().Sub(v.Created) > 10*time.Minute {
		problem(w, 403, "reauthentication_required")
		return
	}
	out, err := s.store.UpdateConsoleUser(r.Context(), u.ID, id, b.Role, b.Status, b.Confirm, b.Version)
	if err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, out)
}
func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request, u database.ConsoleUser, _ session) {
	id := r.PathValue("id")
	if !identity.Valid(id) {
		problem(w, 400, "invalid_request")
		return
	}
	if !decode(w, r, &struct{}{}) {
		return
	}
	if err := s.store.RevokeConsoleSessions(r.Context(), u.ID, id); err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, struct{}{})
}
