package console

import (
	"context"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

// Counter differences are average rates over the two observed collection times,
// never instantaneous speed or bandwidth capacity. Detected resets stay null.
func counterTraffic(previous, current string, before, at, received, now int64) publicTraffic {
	var out publicTraffic
	seconds := at - before
	if seconds <= 0 || seconds > 120 || now-received > 120 || received > now {
		return out
	}
	a, err := protocol.DecodeMeasurements([]byte(previous))
	if err != nil {
		return out
	}
	b, err := protocol.DecodeMeasurements([]byte(current))
	if err != nil || len(a.Networks) == 0 || len(a.Networks) != len(b.Networks) {
		return out
	}
	old := map[string]protocol.NetworkStats{}
	for _, n := range a.Networks {
		old[n.Interface] = n
	}
	var rx, tx float64
	for _, n := range b.Networks {
		p, ok := old[n.Interface]
		if !ok || !p.Available || !n.Available || n.RXBytes < p.RXBytes || n.TXBytes < p.TXBytes {
			return out
		}
		rx += float64(n.RXBytes - p.RXBytes)
		tx += float64(n.TXBytes - p.TXBytes)
	}
	out.AsOf = ptr(received)
	out.Inbound, out.Outbound = ptr(rx*8/float64(seconds)), ptr(tx*8/float64(seconds))
	return out
}

func (s *Server) latestTraffic(ctx context.Context, now int64) (map[string]publicTraffic, error) {
	// Search the indexed, recent receipt window per public node, not the
	// fleet's entire retained task history on every dashboard refresh.
	rows, err := s.store.DB.QueryContext(ctx, `WITH public_nodes AS (
 SELECT p.node_id,p.public_id FROM console_nodes p JOIN nodes n ON n.id=p.node_id
 WHERE n.last_seen_at>0 ORDER BY p.public_id LIMIT 1001
 ) SELECT p.public_id,r.payload,r.completed_at,r.received_at
 FROM public_nodes p JOIN results r ON r.task_id IN (
 SELECT recent.task_id FROM results recent JOIN tasks t ON t.id=recent.task_id
 WHERE recent.node_id=p.node_id AND recent.received_at>=? AND recent.received_at<=?
 AND t.task_type='system.metrics' AND recent.status='SUCCEEDED'
 ORDER BY recent.completed_at DESC,recent.task_id DESC LIMIT 2
 ) ORDER BY p.public_id,r.completed_at DESC,r.task_id DESC`, now-240, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type sample struct {
		raw          string
		at, received int64
	}
	latest := map[string]sample{}
	out := map[string]publicTraffic{}
	for rows.Next() {
		var id string
		var v sample
		if err = rows.Scan(&id, &v.raw, &v.at, &v.received); err != nil {
			return nil, err
		}
		if current, ok := latest[id]; ok {
			out[id] = counterTraffic(v.raw, current.raw, v.at, current.at, current.received, now)
		} else {
			latest[id] = v
		}
	}
	return out, rows.Err()
}
