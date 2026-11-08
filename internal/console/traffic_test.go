package console

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestCounterTrafficPreservesMissingIntervalsAndCapacity(t *testing.T) {
	encode := func(rx, tx uint64, name string) string {
		b, _ := json.Marshal(protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{{Interface: name, Available: true, RXBytes: rx, TXBytes: tx}}})
		return string(b)
	}
	a, b := encode(100, 200, "eth0"), encode(700, 1400, "eth0")
	v := counterTraffic(a, b, 100, 160, 161, 162)
	if v.Inbound == nil || *v.Inbound != 80 || *v.Outbound != 160 || v.InboundCapacity != nil || v.Coverage != nil {
		t.Fatal(v)
	}
	for _, v := range []publicTraffic{counterTraffic(b, a, 100, 160, 161, 162), counterTraffic(a, b, 100, 100, 101, 102), counterTraffic(a, b, 100, 300, 301, 302), counterTraffic(a, b, 100, 160, 161, 300), counterTraffic(a, encode(700, 1400, "eth1"), 100, 160, 161, 162)} {
		if v.Inbound != nil || v.Outbound != nil {
			t.Fatal("fabricated traffic", v)
		}
	}
}

func TestLatestTrafficSelectsRecentSamplesWithoutExposingInterfaceNames(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := database.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := New(store, Config{Origin: "https://console.example", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	sql := func(query string, args ...any) {
		t.Helper()
		if _, e := store.DB.Exec(query, args...); e != nil {
			t.Fatal(e)
		}
	}
	sql(`INSERT INTO nodes(id,hostname,certificate_fingerprint,status,last_seen_at,created_at,certificate_expires_at,certificate) VALUES('node','private','fp','active',1000,1,2000,'cert')`)
	for i, at := range []int64{100, 940, 1000} {
		id := []string{"old", "before", "current"}[i]
		payload, _ := json.Marshal(protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{{Interface: "private0", Available: true, RXBytes: uint64(i) * 600, TXBytes: uint64(i) * 1200}}})
		sql(`INSERT INTO tasks(id,node_id,task_type,parameters,status,created_at,dispatch_expires_at,execution_timeout_ms,result_due_at) VALUES(?,'node','system.metrics','{}','SUCCEEDED',?,2000,1000,2100)`, id, at)
		sql(`INSERT INTO results(task_id,node_id,status,payload,error,completed_at,received_at) VALUES(?,'node','SUCCEEDED',?,'',?,?)`, id, string(payload), at, at)
	}
	traffic, err := s.latestTraffic(t.Context(), 1001)
	if err != nil || len(traffic) != 1 {
		t.Fatal(traffic, err)
	}
	for _, v := range traffic {
		if v.Inbound == nil || *v.Inbound != 80 || v.Outbound == nil || *v.Outbound != 160 {
			t.Fatal(v)
		}
	}
	sql(`UPDATE nodes SET last_seen_at=0`)
	traffic, err = s.latestTraffic(t.Context(), 1001)
	if err != nil || len(traffic) != 0 {
		t.Fatal("unseen node exposed", traffic, err)
	}
}
