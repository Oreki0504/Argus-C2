package signing

import (
	"errors"
	"time"
)

type KeyHealth struct {
	ID               string `json:"key_id"`
	NotBefore        int64  `json:"not_before,omitempty"`
	NotAfter         int64  `json:"not_after,omitempty"`
	RemainingSeconds int64  `json:"remaining_seconds,omitempty"`
	State            string `json:"state"`
}

type HealthReport struct {
	Version    int         `json:"version"`
	CheckedAt  int64       `json:"checked_at"`
	TrustID    string      `json:"trust_set_id,omitempty"`
	Generation int         `json:"generation,omitempty"`
	Selected   string      `json:"selected_key_id,omitempty"`
	State      string      `json:"state"`
	Issues     []string    `json:"issues"`
	Keys       []KeyHealth `json:"keys"`
}

// Inspect reads public local trust only. Selected is supplied by the operator;
// this snapshot cannot establish which key a running server is using.
func Inspect(path, selected string, warnBefore time.Duration, now time.Time) (HealthReport, error) {
	if now.IsZero() {
		now = time.Now()
	}
	r := HealthReport{Version: 1, CheckedAt: now.Unix(), Selected: selected, State: "ok", Issues: []string{}, Keys: []KeyHealth{}}
	if warnBefore < 0 || warnBefore > 90*24*time.Hour {
		return r, errors.New("warning window must be 0 through 90 days")
	}
	legacy, trust, err := LoadVerification(path)
	if err != nil {
		return r, err
	}
	if trust == nil {
		id := KeyID(legacy)
		r.Keys = append(r.Keys, KeyHealth{ID: id, State: "no_expiry"})
		r.State = "warning"
		r.Issues = append(r.Issues, "legacy_key_has_no_expiry")
		if selected != "" && selected != id {
			r.State = "blocked"
			r.Issues = append(r.Issues, "selected_key_not_active")
		}
		return r, nil
	}
	r.TrustID, r.Generation = trust.ID, trust.Generation
	active, selectedActive := false, selected == ""
	for _, key := range trust.Keys {
		state := "ok"
		current := now.Unix() >= key.NotBefore && now.Unix() < key.NotAfter
		active = active || current
		selectedActive = selectedActive || (key.ID == selected && current)
		switch {
		case now.Unix() < key.NotBefore:
			state = "not_yet_valid"
		case now.Unix() >= key.NotAfter:
			state = "expired"
		case now.Add(warnBefore).Unix() >= key.NotAfter:
			state = "expiring"
		}
		if state != "ok" {
			r.State = "warning"
		}
		r.Keys = append(r.Keys, KeyHealth{key.ID, key.NotBefore, key.NotAfter, key.NotAfter - now.Unix(), state})
	}
	if !active {
		r.State = "blocked"
		r.Issues = append(r.Issues, "no_active_key")
	}
	if !selectedActive {
		r.State = "blocked"
		r.Issues = append(r.Issues, "selected_key_not_active")
	}
	return r, nil
}
