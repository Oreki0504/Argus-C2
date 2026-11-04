package transport

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestErrorsDoNotExposeUntrustedResponseBodies(t *testing.T) {
	for _, body := range []string{`{"code":"result_conflict","error":"SECRET-TOKEN"}`, `{"code":"SECRET-TOKEN","error":"SECRET-TOKEN"}`, `{"code":"result_conflict","code":"result_invalid","error":"SECRET-TOKEN"}`, strings.Repeat("SECRET-TOKEN", 1000)} {
		c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 409, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})}
		_, e := Request(t.Context(), c, "https://example.test", "", "GET", "/v1/health", nil)
		if e == nil || strings.Contains(e.Error(), "SECRET-TOKEN") {
			t.Fatal("error leaked response", e)
		}
		var failure *APIError
		if !errors.As(e, &failure) {
			t.Fatal(e)
		}
		if len(body) > 1024 && failure.Code != "" {
			t.Fatal("unbounded error parsed")
		}
	}
}
