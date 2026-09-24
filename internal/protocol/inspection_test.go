package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func inspectionResult(kind TaskType) Result {
	r, _ := DecodeResult(resultSeed())
	r.Type = kind
	r.Status = Succeeded
	r.ErrorCode = ""
	if kind == SSHAudit {
		r.Data, _ = json.Marshal(SSHReport{ProfileID: "host", ObservedAt: 1, Coverage: "complete", Files: []SSHFileObservation{{ID: "keys", Kind: "authorized_keys", Status: "ok", MetadataAvailable: true, Metadata: FileMetadata{Mode: 0600, Size: 100}, SHA256: strings.Repeat("a", 64), Baseline: "unconfigured", Keys: []KeyObservation{{Line: 1, Type: "ssh-ed25519", Fingerprint: "SHA256:" + strings.Repeat("A", 43)}}, Directives: []DirectiveObservation{}, Findings: []string{}}}})
	} else {
		r.Data, _ = json.Marshal(ServiceReport{ServiceID: "host", ObservedAt: 1, Available: true, Unit: "sshd.service", LoadState: "loaded", ActiveState: "active", SubState: "running"})
	}
	return r
}
func TestInspectionSchemasRejectNestedOrUnboundedData(t *testing.T) {
	for _, kind := range []TaskType{SSHAudit, ServiceStatus} {
		r := inspectionResult(kind)
		b, _ := json.Marshal(r)
		if _, err := DecodeResult(b); err != nil {
			t.Fatal(err)
		}
		pairs := [][2]string{{`"observed_at":1`, `"observed_at":3`}, {`"data":{`, `"data":{"path":"/etc/shadow",`}}
		if kind == SSHAudit {
			pairs = append(pairs, [][2]string{
				{`"metadata":{`, `"metadata":{"secret":true,`}, {`"line":1`, `"line":1,"line":1`},
				{`"has_options":false`, `"has_options":null`}, {`"line":1`, `"line":513`},
				{`"type":"ssh-ed25519"`, `"type":""`}, {`"coverage":"complete"`, `"coverage":"unavailable"`},
				{`"findings":[]`, `"findings":["unknown"]`}, {`"baseline":"unconfigured"`, `"baseline":"unavailable"`},
			}...)
		} else {
			pairs = append(pairs, [2]string{`"available":true`, `"available":false`}, [2]string{`"active_state":"active"`, `"active_state":"arbitrary text"`})
		}
		for _, pair := range pairs {
			bad := bytes.Replace(b, []byte(pair[0]), []byte(pair[1]), 1)
			if bytes.Equal(b, bad) {
				t.Fatal("invalid test mutation")
			}
			if _, err := DecodeResult(bad); err == nil {
				t.Fatalf("accepted %s", bad)
			}
		}
	}
}
