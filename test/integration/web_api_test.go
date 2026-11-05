package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

func TestTaskPageAndJSONMediaType(t *testing.T) {
	f := newFleet(t)
	r := f.enroll("agent", policy.Default())
	for range 3 {
		f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
	}
	path := "/v1/tasks?order=newest&limit=2&status=PENDING&node_id=" + url.QueryEscape(r.Engine.State.NodeID)
	var page database.TaskPage
	if err := json.Unmarshal(f.call(f.readToken, "GET", path, nil), &page); err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatal(page, err)
	}
	if err := json.Unmarshal(f.call(f.readToken, "GET", path+"&cursor="+page.NextCursor, nil), &page); err != nil || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	for _, q := range []string{"order=newest&limit=0", "order=newest&status=healthy", "order=newest&limit=2&limit=3", "status=FAILED", "order=newest&after=a", "order=newest&unknown=1"} {
		_, err := transport.Request(t.Context(), f.client, f.url, f.readToken, "GET", "/v1/tasks?"+q, nil)
		wantStatus(t, err, 400)
	}
	for _, tc := range []struct {
		media string
		code  int
	}{{"application/json; charset=utf-8", 200}, {"Application/JSON; charset=\"UTF-8\"", 200}, {"text/plain", 400}, {"application/json; charset=utf-16", 400}, {"application/json; broken", 400}, {"", 400}} {
		req, err := http.NewRequestWithContext(t.Context(), "POST", f.url+"/v1/enrollment-tokens", strings.NewReader(`{"ttl_seconds":60}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.adminToken)
		req.Header.Set("Content-Type", tc.media)
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Fatal(tc, resp.StatusCode)
		}
	}
}
