package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
)

func validHeartbeat() Heartbeat {
	n := identity.New()
	return Heartbeat{Version: 1, AgentID: n.AgentID, EnrollmentEpoch: n.EnrollmentEpoch, SentAt: time.Now().Unix(),
		Info:    SystemInformation{Available: true, OS: "linux", Architecture: "amd64", Hostname: "node", Kernel: "test", BootTime: 1},
		Metrics: SystemMeasurements{CPU: CPUStats{Available: true, BusyPercent: 25, WindowMS: 1000}, Memory: MemoryStats{Available: true, TotalBytes: 1024, AvailableBytes: 512}, Disks: []DiskStats{{Path: "/", Available: true, TotalBytes: 1024, AvailableBytes: 512}}, Networks: []NetworkStats{{Interface: "lo", Available: true, RXBytes: 1, TXBytes: 2}}}}
}
func TestStrictTelemetry(t *testing.T) {
	b, err := json.Marshal(validHeartbeat())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeHeartbeat(b); err != nil {
		t.Fatal(err)
	}
	s := string(b)
	cases := []string{
		strings.Replace(s, `"cpu":`, `"CPU":`, 1),
		strings.Replace(s, `"rx_bytes":1`, `"RX_BYTES":1`, 1),
		strings.Replace(s, `"busy_percent":25`, `"busy_percent":101`, 1),
		strings.Replace(s, `"available_bytes":512`, `"available_bytes":2048`, 1),
		strings.Replace(s, `"disks":[{`, `"disks":null,"unused":[{`, 1),
		strings.Replace(s, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(s, `"version":1`, `"version":1.0`, 1),
		strings.Replace(s, `"hostname":"node"`, `"hostname":"node\nspoofed"`, 1),
		strings.Replace(s, `"kernel":"test"`, `"kernel":"test","url":"https://example.com"`, 1),
		strings.Replace(s, `"available":true`, `"available":false`, 1),
		s + "{}", strings.Repeat(" ", MaxHeartbeatBytes) + s,
	}
	for i, bad := range cases {
		if _, err := DecodeHeartbeat([]byte(bad)); err == nil {
			t.Fatalf("accepted malformed telemetry case %d", i)
		}
	}
}
func FuzzDecodeHeartbeat(f *testing.F) {
	b, _ := json.Marshal(validHeartbeat())
	f.Add(b)
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if h, err := DecodeHeartbeat(data); err == nil {
			if err := h.Validate(); err != nil {
				t.Fatal("decoder accepted invalid heartbeat")
			}
		}
	})
}

func TestStrictEnrollmentMessages(t *testing.T) {
	token := strings.Repeat("a", 64)
	valid := `{"version":1,"token":"` + token + `","csr_b64":"AQID"}`
	if _, _, err := DecodeEnrollmentRequest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(valid, `"token"`, `"TOKEN"`, 1), strings.Replace(valid, "AQID", "AQID=", 1), strings.Replace(valid, `"version":1`, `"version":2`, 1), strings.Replace(valid, token, "short", 1), strings.Replace(valid, "AQID", `AQ\nID`, 1)} {
		if _, _, err := DecodeEnrollmentRequest([]byte(bad)); err == nil {
			t.Fatal("accepted malformed enrollment")
		}
	}
}
