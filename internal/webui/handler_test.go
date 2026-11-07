package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestStaticBoundary(t *testing.T) {
	handler := staticHandler(fstest.MapFS{
		"index.html":               {Data: []byte("<html>Console</html>")},
		"assets/index-abc12345.js": {Data: []byte("const app = true;")},
	})
	for _, tc := range []struct {
		method, path string
		status       int
		cache        string
	}{
		{"GET", "/", 200, "no-store"},
		{"GET", "/setup", 200, "no-store"},
		{"GET", "/fleet/srv-1", 200, "no-store"},
		{"HEAD", "/login", 200, "no-store"},
		{"GET", "/assets/index-abc12345.js", 200, "public, max-age=31536000, immutable"},
		{"GET", "/assets/missing.js", 404, "no-store"},
		{"GET", "/assets/", 404, "no-store"},
		{"GET", "/mockServiceWorker.js", 404, "no-store"},
		{"GET", "/v1", 404, "no-store"},
		{"GET", "/v1/me", 404, "no-store"},
		{"GET", "/v1/agent/poll", 404, "no-store"},
		{"GET", "/v1/unknown", 404, "no-store"},
		{"POST", "/setup", 405, "no-store"},
		{"GET", "/../index.html", 404, "no-store"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := httptest.NewRecorder()
			handler.ServeHTTP(r, httptest.NewRequest(tc.method, tc.path, nil))
			if r.Code != tc.status || r.Header().Get("Cache-Control") != tc.cache {
				t.Fatalf("status/cache: %d %q", r.Code, r.Header().Get("Cache-Control"))
			}
			if r.Header().Get("Content-Security-Policy") != contentSecurityPolicy || r.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing security headers")
			}
			if tc.method == "HEAD" && r.Body.Len() != 0 {
				t.Fatal("HEAD has body")
			}
			if tc.status != 200 && strings.Contains(r.Body.String(), "<html>") {
				t.Fatal("SPA leaked to error route")
			}
		})
	}
}

func TestBuildHandler(t *testing.T) {
	r := httptest.NewRecorder()
	Handler().ServeHTTP(r, httptest.NewRequest("GET", "/", nil))
	want := http.StatusServiceUnavailable
	if Available {
		want = http.StatusOK
	}
	if r.Code != want {
		t.Fatalf("got %d, want %d", r.Code, want)
	}
}
