package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNestedMetricsRemainStrict(t *testing.T) {
	good := SystemMeasurements{CPU: CPUStats{Available: true, BusyPercent: 25, WindowMS: 1000}, Memory: MemoryStats{Available: true, TotalBytes: 1024, AvailableBytes: 512}, Disks: []DiskStats{{Path: "/", Available: true, TotalBytes: 1024, AvailableBytes: 512}}, Networks: []NetworkStats{{Interface: "lo", Available: true, RXBytes: 1, TXBytes: 2}}}
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeMeasurements(raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{`"cpu":`, `"CPU":`}, {`"rx_bytes":1`, `"RX_BYTES":1`}, {`"busy_percent":25`, `"busy_percent":101`}, {`"available_bytes":512`, `"available_bytes":2048`}, {`"disks":[{`, `"disks":null,"unused":[{`}, {`"window_ms":1000`, `"window_ms":1000,"window_ms":1000`}, {`"interface":"lo"`, `"interface":"lo\n"`}, {`"available":true`, `"available":false`}} {
		bad := strings.Replace(string(raw), change[0], change[1], 1)
		if _, err = DecodeMeasurements([]byte(bad)); err == nil {
			t.Fatal("accepted invalid metrics", bad)
		}
	}
}
func FuzzDecodeMeasurements(f *testing.F) {
	f.Add([]byte(`{"cpu":{"available":false,"busy_percent":0,"window_ms":0},"memory":{"available":false,"total_bytes":0,"available_bytes":0},"disks":[],"networks":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, e := DecodeMeasurements(b); e == nil {
			if e = m.Validate(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
