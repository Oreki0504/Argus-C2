package console

import (
	"errors"
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/oauth2"
)

type githubHTTPError struct{ status int }

func (githubHTTPError) Error() string { return "GitHub user API rejected the request" }

// OAuth errors can contain credentials, response bodies and request URLs.
// Emit only fixed classifications and status codes, never the original error.
func reportGitHubFailure(stage string, err error) string {
	reason, category, status := "github_exchange_failed", "invalid_response", 0
	if stage == "user_info" {
		reason = "github_profile_failed"
	}
	var upstream *oauth2.RetrieveError
	var profile githubHTTPError
	var network net.Error
	if errors.As(err, &upstream) {
		if upstream.Response != nil {
			status = upstream.Response.StatusCode
		}
		category = "provider_rejected"
		switch upstream.ErrorCode {
		case "incorrect_client_credentials", "invalid_client":
			reason, category = "github_client_invalid", "client_credentials"
		case "redirect_uri_mismatch":
			reason, category = "github_redirect_mismatch", "redirect_uri"
		case "bad_verification_code", "invalid_grant":
			reason, category = "github_code_rejected", "authorization_code"
		case "unverified_user_email":
			reason, category = "github_email_unverified", "email_unverified"
		}
	} else if errors.As(err, &profile) {
		status, category = profile.status, "provider_rejected"
	} else if errors.As(err, &network) {
		reason, category = "github_unavailable", "network"
		if network.Timeout() {
			category = "timeout"
		}
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		reason, category = "github_unavailable", "upstream_unavailable"
	}
	slog.Warn("Console OAuth failed", "provider", "github", "stage", stage,
		"category", category, "upstream_status", status, "reason", reason)
	return reason
}
