package api

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func (s *Server) tasks(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		problem(w, 400, "invalid task query")
		return
	}
	for k, v := range values {
		if len(v) != 1 {
			problem(w, 400, "duplicate task query parameter")
			return
		}
		switch k {
		case "order", "after", "cursor", "limit", "node_id", "status", "created_after", "created_before":
		default:
			problem(w, 400, "unknown task query parameter")
			return
		}
	}
	order := values.Get("order")
	if order == "" || order == "id" {
		for k := range values {
			if k != "order" && k != "after" {
				problem(w, 400, "filters require order=newest")
				return
			}
		}
		out, e := s.Store.Tasks(r.Context(), values.Get("after"))
		reply(w, out, e)
		return
	}
	if order != "newest" || values.Has("after") {
		problem(w, 400, "invalid task order or cursor combination")
		return
	}
	q := database.TaskQuery{NodeID: values.Get("node_id"), Status: protocol.TaskStatus(values.Get("status")), Cursor: values.Get("cursor"), Limit: 20}
	if values.Has("limit") {
		q.Limit, err = strconv.Atoi(values.Get("limit"))
		if err != nil {
			problem(w, 400, "invalid limit")
			return
		}
	}
	for name, dest := range map[string]*int64{"created_after": &q.CreatedAfter, "created_before": &q.CreatedBefore} {
		if values.Has(name) {
			*dest, err = strconv.ParseInt(values.Get(name), 10, 64)
			if err != nil {
				problem(w, 400, "invalid time filter")
				return
			}
		}
	}
	if err = q.Validate(); err != nil {
		problem(w, 400, "invalid task query or cursor")
		return
	}
	out, err := s.Store.QueryTasks(r.Context(), q)
	reply(w, out, err)
}
