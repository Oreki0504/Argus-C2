package agent

import "testing"

func TestServerOrigin(t *testing.T) {
	for _, raw := range []string{"https://localhost:8443", "https://127.0.0.1:8443/", "https://[::1]:8443"} {
		if _, err := ServerURL(raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"http://localhost:8443", "https://user:password@localhost", "https://localhost/path", "https://localhost?", "https://localhost?x=1", "https://localhost#fragment", "https:///", "https://localhost/%2f", "file:///tmp/server"} {
		if _, err := ServerURL(raw); err == nil {
			t.Fatalf("accepted invalid origin %s", raw)
		}
	}
}
