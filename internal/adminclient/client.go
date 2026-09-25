// Package adminclient implements verified, bounded administrator HTTPS calls.
package adminclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/adminauth"
	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/audit"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/management"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

type Client struct {
	http           *http.Client
	Origin, CAHash string
}
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("administrator API returned %d (%s)", e.Status, e.Code)
}
func New(origin, ca string) (*Client, error) {
	u, err := agent.ServerURL(origin)
	if err != nil {
		return nil, err
	}
	config, err := tlsconfig.AdministrationClient(ca, u.Hostname())
	if err != nil {
		return nil, err
	}
	data, err := localfile.Read(ca, 64*1024, false)
	if err != nil {
		return nil, err
	}
	return newClient(u.String(), audit.Digest(data), config), nil
}
func newClient(origin, caHash string, config *tls.Config) *Client {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: config.Clone(), DisableCompression: true, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 1, MaxResponseHeaderBytes: 8192}
	return &Client{http: &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("administrator redirects are forbidden") }}, Origin: origin, CAHash: caHash}
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) Request(ctx context.Context, token, method, path string, data []byte) ([]byte, error) {
	if !strings.HasPrefix(path, "/api/v1/") || len(path) > 512 || (method != http.MethodGet && method != http.MethodPost) || len(data) > management.MaxRequestBytes {
		return nil, errors.New("invalid administrator request")
	}
	if token != "" && !identity.Hex(token, 64) {
		return nil, errors.New("invalid session token")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Origin+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("administrator HTTPS request failed")
	}
	defer resp.Body.Close()
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || resp.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("invalid administrator response framing")
	}
	result, err := strictjson.Read(resp.Body, management.MaxResponseBytes)
	if err != nil {
		return nil, errors.New("administrator response exceeds bounds")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code string `json:"code"`
		}
		if strictjson.Decode(result, &e, 256, "code") != nil {
			return nil, errors.New("invalid administrator error response")
		}
		switch e.Code {
		case "unauthorized", "forbidden", "rate_limited", "invalid_request", "not_found", "operation_rejected", "unavailable", "method_not_allowed":
		default:
			e.Code = "unknown"
		}
		return nil, &APIError{resp.StatusCode, e.Code}
	}
	if !json.Valid(result) {
		return nil, errors.New("invalid administrator JSON response")
	}
	return result, nil
}
func (c *Client) Login(ctx context.Context, name, password string) (state.Login, error) {
	data, err := json.Marshal(management.LoginRequest{Username: name, Password: password})
	if err != nil {
		return state.Login{}, err
	}
	b, err := c.Request(ctx, "", http.MethodPost, management.LoginPath, data)
	if err != nil {
		return state.Login{}, err
	}
	return decodeLogin(b)
}
func decodeLogin(b []byte) (state.Login, error) {
	var value state.Login
	if err := strictjson.Decode(b, &value, 2048, "token", "user", "expires_at", "idle_seconds"); err != nil {
		return value, err
	}
	var raw struct {
		User json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return value, err
	}
	if err := strictjson.Decode(raw.User, &value.User, 512, "id", "username", "role", "enabled"); err != nil {
		return value, err
	}
	if !identity.Hex(value.Token, 64) || !identity.Hex(value.User.ID, 32) || !adminauth.Username(value.User.Username) || !adminauth.Role(value.User.Role) || !value.User.Enabled || value.ExpiresAt < 1 || value.IdleSeconds != 1800 {
		return state.Login{}, errors.New("invalid login response")
	}
	return value, nil
}
