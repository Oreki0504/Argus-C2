// Package agent implements explicit enrollment and outbound authenticated telemetry.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Client struct {
	http   *http.Client
	origin string
	node   identity.Node
}

func ServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("server must be an HTTPS origin without credentials, path, query, or fragment")
	}
	u.Path = ""
	return u, nil
}
func NewClient(raw string, config *tls.Config, node identity.Node) (*Client, error) {
	u, err := ServerURL(raw)
	if err != nil {
		return nil, err
	}
	if node.Validate() != nil || config == nil || config.InsecureSkipVerify || config.MinVersion < tls.VersionTLS13 || config.RootCAs == nil || len(config.Certificates) != 1 || config.ServerName != u.Hostname() {
		return nil, errors.New("verified TLS configuration and matching identity are required")
	}
	cert := config.Certificates[0].Leaf
	actual, err := identity.FromCertificate(cert)
	if err != nil || actual != node {
		return nil, errors.New("TLS certificate identity mismatch")
	}
	return &Client{http: newHTTP(config), origin: u.String(), node: node}, nil
}

func newHTTP(config *tls.Config) *http.Client {
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: config.Clone(), DisableCompression: true,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 1,
		MaxResponseHeaderBytes: 8192,
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are forbidden") }}
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) Connect(ctx context.Context) (protocol.ConnectionInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/api/v1/agent/identity", nil)
	if err != nil {
		return protocol.ConnectionInfo{}, err
	}
	return c.identityResponse(req)
}

func (c *Client) Heartbeat(ctx context.Context, h protocol.Heartbeat) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if h.AgentID != c.node.AgentID || h.EnrollmentEpoch != c.node.EnrollmentEpoch {
		return errors.New("local heartbeat identity mismatch")
	}
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxHeartbeatBytes {
		return errors.New("heartbeat exceeds size limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/v1/agent/heartbeat", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = c.identityResponse(req)
	return err
}

func (c *Client) identityResponse(req *http.Request) (protocol.ConnectionInfo, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return protocol.ConnectionInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.ConnectionInfo{}, errors.New("server rejected probe request")
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return protocol.ConnectionInfo{}, errors.New("expected JSON response")
	}
	data, err := strictjson.Read(resp.Body, 4096)
	if err != nil {
		return protocol.ConnectionInfo{}, err
	}
	info, err := protocol.DecodeConnectionInfo(data)
	if err != nil {
		return protocol.ConnectionInfo{}, err
	}
	if info.AgentID != c.node.AgentID || info.EnrollmentEpoch != c.node.EnrollmentEpoch {
		return protocol.ConnectionInfo{}, errors.New("server returned a different node identity")
	}
	return info, nil
}
