package console

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestGitHubFailureClassificationNeverLogsProviderSecrets(t *testing.T) {
	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&log, nil)))
	defer slog.SetDefault(old)
	for _, tc := range []struct{ code, reason string }{
		{"incorrect_client_credentials", "github_client_invalid"}, {"redirect_uri_mismatch", "github_redirect_mismatch"},
		{"bad_verification_code", "github_code_rejected"}, {"unverified_user_email", "github_email_unverified"},
		{"private-secret", "github_exchange_failed"},
	} {
		err := &oauth2.RetrieveError{Response: &http.Response{StatusCode: 400}, Body: []byte("private-secret"), ErrorCode: tc.code, ErrorDescription: "private-secret", ErrorURI: "https://example.com/?code=private-secret"}
		if got := reportGitHubFailure("token_exchange", err); got != tc.reason {
			t.Fatal(got)
		}
	}
	if got := reportGitHubFailure("user_info", githubHTTPError{503}); got != "github_unavailable" {
		t.Fatal(got)
	}
	if got := reportGitHubFailure("user_info", &url.Error{Op: "Get", URL: "https://example.com/?token=private-secret", Err: errors.New("private-secret")}); got != "github_unavailable" {
		t.Fatal(got)
	}
	if strings.Contains(log.String(), "private-secret") || strings.Contains(log.String(), "https://") {
		t.Fatal("raw provider error leaked", log.String())
	}
}
