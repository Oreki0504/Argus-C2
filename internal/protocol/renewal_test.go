package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenewalStrictParsing(t *testing.T) {
	good := `{"version":1,"renewal_id":"` + strings.Repeat("a", 32) + `","csr_b64":"AQ"}`
	if _, _, err := DecodeRenewalRequest([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"version":1`, `"version":2`, 1),
		strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(good, `"version":1`, `"Version":1`, 1),
		strings.Replace(good, `"version":1`, `"version":1,"agent_id":"chosen"`, 1),
		strings.Replace(good, `"AQ"`, `"AQ=="`, 1),
		strings.Replace(good, `"AQ"`, `"AR"`, 1),
		strings.Replace(good, `"AQ"`, `null`, 1), good + `{}`, strings.Repeat(" ", MaxRenewalBytes) + good,
	} {
		if _, _, err := DecodeRenewalRequest([]byte(bad)); err == nil {
			t.Fatal("accepted ambiguous renewal request")
		}
	}
	r := RenewalResponse{Version: 1, RenewalID: strings.Repeat("a", 32), AgentID: strings.Repeat("b", 32), Epoch: strings.Repeat("c", 32), Generation: 2, PreviousSHA256: strings.Repeat("d", 64), PreviousValidUntil: 1, CertificatePEM: "certificate"}
	data, _ := json.Marshal(r)
	if _, err := DecodeRenewalResponse(data); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{`,"root_ca":"replace"}`, `,"path":"/etc/passwd"}`, `,"policy":{}}`} {
		bad := string(data[:len(data)-1]) + suffix
		if _, err := DecodeRenewalResponse([]byte(bad)); err == nil {
			t.Fatal("response expanded local authority")
		}
	}
}

func FuzzRenewalMessages(f *testing.F) {
	f.Add([]byte(`{"version":1,"renewal_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","csr_b64":"AQ"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeRenewalRequest(data)
		_, _ = DecodeRenewalResponse(data)
	})
}
