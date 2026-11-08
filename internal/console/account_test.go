package console

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func loginTokenTest(t *testing.T, b *testBrowser, token string) map[string]any {
	t.Helper()
	return decodeTest[map[string]any](t, b.request("POST", "/v1/console/auth/token", map[string]string{"token": token}, b.pre(), nil), 200)
}

func bindCallback(t *testing.T, b *testBrowser, provider, csrf string) string {
	t.Helper()
	decodeTest[map[string]any](t, b.request("POST", "/v1/console/account/bind", map[string]string{"provider": provider}, csrf, nil), 200)
	w := b.request("GET", "/v1/console/auth/redirect", nil, "", nil)
	if w.Code != 303 {
		t.Fatal(w.Code)
	}
	client := *b.s.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != 303 {
		t.Fatal("provider redirect", err)
	}
	return callback.RequestURI()
}

func TestTokenOwnerThenBothProvidersBindSameAccount(t *testing.T) {
	s, _, _, _, _, settings := socialConsole(t)
	secret, err := s.store.IssueConsoleToken(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t, s)
	// No provider setup, discovery or short-lived bootstrap is needed.
	owner := loginTokenTest(t, b, secret)
	if owner["role"] != "Admin" {
		t.Fatal(owner)
	}
	id := owner["principal_id"]
	csrf := owner["csrf_token"].(string)
	if w := b.request("POST", "/v1/console/account/providers", settings, "wrong", nil); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	response := b.request("POST", "/v1/console/account/providers", settings, csrf, nil)
	decodeTest[map[string]any](t, response, 200)
	if strings.Contains(response.Body.String(), "test-secret") || strings.Contains(response.Body.String(), "github-secret") {
		t.Fatal("secret exposed")
	}
	for _, provider := range []string{"google", "github"} {
		callback := bindCallback(t, b, provider, csrf)
		if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/account?bound=1" {
			t.Fatal(dest)
		}
		if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest == "/account?bound=1" {
			t.Fatal("callback replay")
		}
	}
	items, err := s.store.ConsoleIdentities(context.Background(), id.(string))
	if err != nil || len(items) != 2 {
		t.Fatal(items, err)
	}
	decodeTest[map[string]any](t, b.request("POST", "/v1/console/auth/logout", struct{}{}, csrf, nil), 200)
	for _, provider := range []string{"google", "github"} {
		callback := startSocial(t, b, provider, b.pre(), false)
		if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/" {
			t.Fatal(dest)
		}
		if me := b.identity(); me["principal_id"] != id || me["role"] != "Admin" {
			t.Fatal("identity changed", me)
		}
	}
	// The same token survives restart and still authenticates the same owner.
	restarted, err := New(s.store, s.config)
	if err != nil {
		t.Fatal(err)
	}
	if me := loginTokenTest(t, newBrowser(t, restarted), secret); me["principal_id"] != id {
		t.Fatal("token changed account")
	}
}

func TestAccountBindingRejectsLogoutRevocationAndIdentityTakeover(t *testing.T) {
	for _, mode := range []string{"logout", "recovery", "provider_change", "identity_conflict"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _, _, _, settings := socialConsole(t)
			secret, err := s.store.IssueConsoleToken(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			b := newBrowser(t, s)
			owner := loginTokenTest(t, b, secret)
			csrf := owner["csrf_token"].(string)
			decodeTest[map[string]any](t, b.request("POST", "/v1/console/account/providers", settings, csrf, nil), 200)
			if mode == "identity_conflict" {
				other := newBrowser(t, s)
				callback := startSocial(t, other, "github", other.pre(), false)
				if dest := other.request("GET", callback, nil, "", nil).Header().Get("Location"); dest != "/login?reason=account_pending" {
					t.Fatal(dest)
				}
			}
			callback := bindCallback(t, b, "github", csrf)
			switch mode {
			case "logout":
				decodeTest[map[string]any](t, b.request("POST", "/v1/console/auth/logout", struct{}{}, csrf, nil), 200)
			case "recovery":
				if _, err = s.store.IssueConsoleToken(context.Background(), true); err != nil {
					t.Fatal(err)
				}
			case "provider_change":
				decodeTest[map[string]any](t, b.request("POST", "/v1/console/account/providers", settings, csrf, nil), 200)
			}
			if dest := b.request("GET", callback, nil, "", nil).Header().Get("Location"); dest == "/account?bound=1" {
				t.Fatal("invalid binding accepted")
			}
			items, err := s.store.ConsoleIdentities(context.Background(), owner["principal_id"].(string))
			if err != nil || len(items) != 0 {
				t.Fatal("identity transferred", err)
			}
		})
	}
}

func TestTokenLoginBoundaries(t *testing.T) {
	s, _, _, _, _, _ := socialConsole(t)
	secret, err := s.store.IssueConsoleToken(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t, s)
	if w := b.request("POST", "/v1/console/auth/token", map[string]string{"token": secret}, "", nil); w.Code != 403 {
		t.Fatal("CSRF bypass")
	}
	if w := b.request("POST", "/v1/console/auth/token", map[string]string{"token": strings.Repeat("0", 64)}, b.pre(), nil); w.Code != 401 {
		t.Fatal("wrong token accepted")
	}
	owner := loginTokenTest(t, b, secret)
	csrf := owner["csrf_token"].(string)
	newToken, err := s.store.IssueConsoleToken(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if w := b.request("GET", "/v1/me", nil, "", nil); w.Code != 401 {
		t.Fatal("recovery kept old session")
	}
	if w := b.request("POST", "/v1/console/auth/token", map[string]string{"token": secret}, b.pre(), nil); w.Code != 401 {
		t.Fatal("old token accepted")
	}
	newOwner := loginTokenTest(t, b, newToken)
	if newOwner["principal_id"] == owner["principal_id"] {
		t.Fatal("recovery reused owner")
	}
	if w := b.request("POST", "/v1/console/account/bind", map[string]string{"provider": "github"}, csrf, nil); w.Code != 403 {
		t.Fatal("old CSRF accepted")
	}
	// Fresh authentication is required for linking/configuration.
	s.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if w := b.request("POST", "/v1/console/account/bind", map[string]string{"provider": "github"}, newOwner["csrf_token"].(string), nil); w.Code != 403 {
		t.Fatal("stale session accepted")
	}
}
