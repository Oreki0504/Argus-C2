package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestStrictPolicyAndStableDigest(t *testing.T) {
	data, err := os.ReadFile("../../examples/task-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	p.Telemetry.DiskPaths = []string{"/var", "/"}
	p.Telemetry.NetworkInterfaces = []string{"lo", "eth0"}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	p.Telemetry.DiskPaths = []string{"/", "/var"}
	p.Telemetry.NetworkInterfaces = []string{"eth0", "lo"}
	if got, _ := p.Digest(); got != digest {
		t.Fatal("ordering changed authority digest")
	}
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.Paused = true }, func(p *Policy) { p.AllowSystemInfo = false }, func(p *Policy) { p.AllowSystemMetrics = false },
		func(p *Policy) { p.PollSeconds++ }, func(p *Policy) { p.TimeoutSeconds++ }, func(p *Policy) { p.MaxPerMinute-- },
		func(p *Policy) { p.Burst-- }, func(p *Policy) { p.MaxResultBytes-- }, func(p *Policy) { p.PendingBytes-- },
		func(p *Policy) { p.Telemetry.IntervalSeconds++ }, func(p *Policy) { p.Telemetry.SampleMilliseconds++ },
		func(p *Policy) { p.Telemetry.DiskPaths = []string{"/"} }, func(p *Policy) { p.Telemetry.NetworkInterfaces = []string{} },
	} {
		changed := p
		mutate(&changed)
		got, err := changed.Digest()
		if err != nil || got == digest {
			t.Fatal("authority field missing from digest", err)
		}
	}
	compact, _ := json.Marshal(p)
	for _, bad := range [][]byte{
		append(append([]byte{}, compact[:len(compact)-1]...), []byte(`,"command":"id"}`)...),
		bytes.Replace(compact, []byte(`"paused":false`), []byte(`"paused":false,"paused":true`), 1),
		bytes.Replace(compact, []byte(`"paused":false`), []byte(`"paused":null`), 1),
		bytes.Replace(compact, []byte(`"telemetry":{`), []byte(`"telemetry":{"extra":true,`), 1),
		bytes.Replace(compact, []byte(`"burst":5`), []byte(`"burst":99`), 1),
		bytes.Replace(compact, []byte(`"timeout_seconds":5`), []byte(`"timeout_seconds":0`), 1),
	} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
