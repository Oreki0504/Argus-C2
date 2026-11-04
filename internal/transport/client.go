package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"net/http"
	"strconv"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type APIError struct {
	Status int
	Code   string
}

// ResultRejection only classifies explicit, scoped business failures. HTTP
// status alone (including 404/5xx) never discards or parks a result.
func (e *APIError) ResultRejection() bool {
	switch e.Code {
	case "result_conflict", "task_rejected":
		return e.Status == 409
	case "task_not_found":
		return e.Status == 404
	case "result_invalid":
		return e.Status == 400
	}
	return false
}
func knownErrorCode(s string) bool {
	switch s {
	case "invalid_request", "unauthorized", "forbidden", "not_found", "state_conflict", "operation_failed", "server_busy", "result_conflict", "task_rejected", "task_not_found", "result_invalid", "renewal_key_mismatch", "protocol_incompatible":
		return true
	}
	return false
}

func (e *APIError) Error() string {
	if knownErrorCode(e.Code) {
		return fmt.Sprintf("server returned HTTP %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("server returned HTTP %d (unclassified response)", e.Status)
}
func Request(ctx context.Context, c *http.Client, base, token, method, path string, input any) ([]byte, error) {
	if e := ValidateURL(base); e != nil {
		return nil, e
	}
	var data []byte
	var e error
	if input != nil {
		data, e = json.Marshal(input)
		if e != nil {
			return nil, e
		}
	}
	r, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, bytes.NewReader(data))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	agentRequest := strings.HasPrefix(path, "/v1/agent/") || path == "/v1/enroll"
	if agentRequest {
		r.Header.Set(protocol.VersionHeader, strconv.Itoa(protocol.Version))
		r.Header.Set(protocol.AgentVersionHeader, protocol.BuildVersion())
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := c.Do(r)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if agentRequest && (len(res.Header.Values(protocol.VersionHeader)) != 1 || res.Header.Get(protocol.VersionHeader) != strconv.Itoa(protocol.Version)) {
		return nil, errors.New("incompatible server protocol; local state retained")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		failure := &APIError{Status: res.StatusCode}
		raw, readErr := strictjson.Read(res.Body, 1024)
		var body struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if readErr == nil && res.Header.Get("Content-Type") == "application/json" && strictjson.Decode(raw, &body, 1024, "error", "code") == nil && knownErrorCode(body.Code) {
			failure.Code = body.Code
		}
		return nil, failure
	}
	if res.StatusCode == 204 {
		return nil, nil
	}
	limit := 16 * 1024 * 1024
	if strings.HasPrefix(path, "/v1/agent/") || path == "/v1/enroll" {
		limit = 65536
	}
	return strictjson.Read(res.Body, limit)
}
