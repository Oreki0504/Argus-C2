package console

import (
	"database/sql"
	"net/http"
	"regexp"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

// These DTOs intentionally cannot hold hostnames, addresses, paths, interfaces,
// task identifiers or nested raw collector reports. Both User and anonymous
// responses are constructed here before JSON serialization.
type publicSystem struct {
	OS            *string `json:"os"`
	Architecture  *string `json:"architecture"`
	Kernel        *string `json:"kernel"`
	UptimeSeconds *int64  `json:"uptime_seconds"`
}
type publicResources struct {
	AsOf   *int64   `json:"as_of"`
	CPU    *float64 `json:"cpu_percent"`
	Memory *float64 `json:"memory_percent"`
	Disk   *float64 `json:"disk_percent"`
}
type publicTraffic struct {
	AsOf             *int64   `json:"as_of"`
	Inbound          *float64 `json:"inbound_bps"`
	Outbound         *float64 `json:"outbound_bps"`
	InboundCapacity  *float64 `json:"inbound_capacity_bps"`
	OutboundCapacity *float64 `json:"outbound_capacity_bps"`
	InboundBytes     *float64 `json:"sampled_inbound_bytes"`
	OutboundBytes    *float64 `json:"sampled_outbound_bytes"`
	Coverage         *float64 `json:"coverage_percent"`
}
type publicNode struct {
	PublicID    string          `json:"public_id"`
	DisplayName string          `json:"display_name"`
	LastSeenAt  int64           `json:"last_seen_at"`
	System      publicSystem    `json:"system"`
	Resources   publicResources `json:"resources"`
	Traffic     publicTraffic   `json:"traffic"`
}
type publicSummary struct {
	GeneratedAt           int64        `json:"generated_at"`
	WindowStart           int64        `json:"window_start"`
	WindowEnd             int64        `json:"window_end"`
	SampleIntervalSeconds int64        `json:"sample_interval_seconds"`
	Nodes                 []publicNode `json:"nodes"`
}
type historyPoint struct {
	Timestamp int64    `json:"timestamp"`
	CPU       *float64 `json:"cpu_percent"`
	Memory    *float64 `json:"memory_percent"`
	Disk      *float64 `json:"disk_percent"`
	Inbound   *float64 `json:"inbound_percent"`
	Outbound  *float64 `json:"outbound_percent"`
}
type publicHistory struct {
	PublicID              string         `json:"public_id"`
	Range                 string         `json:"range"`
	WindowStart           int64          `json:"window_start"`
	WindowEnd             int64          `json:"window_end"`
	SampleIntervalSeconds int64          `json:"sample_interval_seconds"`
	Points                []historyPoint `json:"points"`
}

func ptr[T any](v T) *T { return &v }

var kernelVersion = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3})(?:[-+].*)?$`)
var osVersion = regexp.MustCompile(`^[0-9]{1,4}(?:\.[0-9]{1,4}){0,2}$`)

func projectSystem(raw string, completed int64) publicSystem {
	var out publicSystem
	i, err := protocol.DecodeInformation([]byte(raw))
	if err != nil || i.Validate(completed) != nil || !i.Available {
		return out
	}
	// Return a small vocabulary, never arbitrary Agent-supplied system text.
	for _, family := range []string{"Ubuntu", "Debian", "Fedora", "Alpine", "Arch", "Rocky", "AlmaLinux", "CentOS", "Red Hat", "openSUSE", "SUSE", "Amazon Linux", "Oracle Linux", "NixOS"} {
		if i.OS == family || strings.HasPrefix(i.OS, family+" ") {
			name := family
			for _, word := range strings.Fields(strings.TrimPrefix(i.OS, family)) {
				if osVersion.MatchString(word) {
					name += " " + word
					break
				}
			}
			out.OS = &name
			break
		}
	}
	switch i.Architecture {
	case "x86_64", "amd64", "aarch64", "arm64", "armv7l", "armv6l", "i386", "i686", "riscv64", "ppc64le", "s390x":
		out.Architecture = ptr(i.Architecture)
	}
	if match := kernelVersion.FindStringSubmatch(i.Kernel); len(match) > 1 {
		out.Kernel = &match[1]
	}
	if completed >= i.BootTime && i.BootTime > 0 {
		out.UptimeSeconds = ptr(completed - i.BootTime)
	}
	return out
}
func projectResources(raw string, received int64) publicResources {
	var out publicResources
	m, err := protocol.DecodeMeasurements([]byte(raw))
	if err != nil {
		return out
	}
	out.AsOf = ptr(received)
	if m.CPU.Available {
		out.CPU = ptr(m.CPU.BusyPercent)
	}
	if m.Memory.Available && m.Memory.TotalBytes > 0 {
		out.Memory = ptr(100 * float64(m.Memory.TotalBytes-m.Memory.AvailableBytes) / float64(m.Memory.TotalBytes))
	}
	complete := len(m.Disks) > 0
	var total, available float64
	for _, d := range m.Disks {
		if !d.Available {
			complete = false
		}
		total += float64(d.TotalBytes)
		available += float64(d.AvailableBytes)
	}
	if complete && total > 0 {
		out.Disk = ptr(100 * (total - available) / total)
	}
	return out
}
func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		problem(w, 400, "invalid_request")
		return
	}
	now := s.now().Unix()
	out := publicSummary{now, now - 3600, now, 60, []publicNode{}}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT p.public_id,p.display_name,n.last_seen_at,
 COALESCE(i.payload,''),COALESCE(i.completed_at,0),COALESCE(m.payload,''),COALESCE(m.received_at,0)
 FROM nodes n JOIN console_nodes p ON p.node_id=n.id
 LEFT JOIN results i ON i.task_id=(SELECT r.task_id FROM results r JOIN tasks t ON t.id=r.task_id WHERE r.node_id=n.id AND r.status='SUCCEEDED' AND t.task_type='system.info' ORDER BY r.received_at DESC,r.task_id DESC LIMIT 1)
 LEFT JOIN results m ON m.task_id=(SELECT r.task_id FROM results r JOIN tasks t ON t.id=r.task_id WHERE r.node_id=n.id AND r.status='SUCCEEDED' AND t.task_type='system.metrics' ORDER BY r.received_at DESC,r.task_id DESC LIMIT 1)
 ORDER BY p.public_id LIMIT 1001`)
	if err != nil {
		storeProblem(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var n publicNode
		var info, metrics string
		var completed, received int64
		if err = rows.Scan(&n.PublicID, &n.DisplayName, &n.LastSeenAt, &info, &completed, &metrics, &received); err != nil {
			storeProblem(w, err)
			return
		}
		// Public names are opaque until a separately validated naming workflow is
		// provided. Do not expose arbitrary database/Agent text as a public name.
		n.DisplayName = publicName("", n.PublicID)
		if info != "" {
			n.System = projectSystem(info, completed)
		}
		if metrics != "" {
			n.Resources = projectResources(metrics, received)
		}
		// Cumulative counters from sporadic diagnostic tasks cannot establish
		// periodic bandwidth/coverage. Network values remain explicitly missing.
		out.Nodes = append(out.Nodes, n)
	}
	if err = rows.Err(); err != nil {
		storeProblem(w, err)
		return
	}
	if len(out.Nodes) > 1000 {
		problem(w, 503, "service_unavailable")
		return
	}
	reply(w, out)
}
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	if !listParams(w, r, "range") {
		return
	}
	if len(r.URL.Query()) != 1 {
		problem(w, 400, "invalid_request")
		return
	}
	id := r.PathValue("id")
	if !identity.Valid(id) {
		problem(w, 404, "not_found")
		return
	}
	window, interval := int64(3600), int64(60)
	span := r.URL.Query().Get("range")
	switch span {
	case "1h":
	case "24h":
		window = 86400
		interval = 300
	case "7d":
		window = 7 * 86400
		interval = 900
	default:
		problem(w, 400, "invalid_request")
		return
	}
	var node string
	err := s.store.DB.QueryRowContext(r.Context(), "SELECT node_id FROM console_nodes WHERE public_id=?", id).Scan(&node)
	if err == sql.ErrNoRows {
		problem(w, 404, "not_found")
		return
	}
	if err != nil {
		storeProblem(w, err)
		return
	}
	now := s.now().Unix()
	out := publicHistory{id, span, now - window, now, interval, []historyPoint{}}
	// Latest real result within each display bucket; never interpolate samples.
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT payload,received_at FROM (
 SELECT r.payload,r.received_at,row_number() OVER (PARTITION BY r.received_at/? ORDER BY r.received_at DESC,r.task_id DESC) AS pos
 FROM results r JOIN tasks t ON t.id=r.task_id WHERE r.node_id=? AND r.status='SUCCEEDED' AND t.task_type='system.metrics' AND r.received_at>=? AND r.received_at<=?
 ) WHERE pos=1 ORDER BY received_at LIMIT 2000`, interval, node, out.WindowStart, now)
	if err != nil {
		storeProblem(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var at int64
		if err = rows.Scan(&raw, &at); err != nil {
			storeProblem(w, err)
			return
		}
		m := projectResources(raw, at)
		out.Points = append(out.Points, historyPoint{Timestamp: at, CPU: m.CPU, Memory: m.Memory, Disk: m.Disk})
	}
	if err = rows.Err(); err != nil {
		storeProblem(w, err)
		return
	}
	reply(w, out)
}
