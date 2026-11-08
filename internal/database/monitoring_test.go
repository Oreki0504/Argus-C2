package database

import (
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestMonitoringUsesIdleQueueAndRateLimitsFailedCollection(t *testing.T) {
	s := fixture(t)
	now := time.Now().Truncate(time.Second)
	s.clock = func() time.Time { return now }
	c := &x509.Certificate{Raw: []byte("monitor-cert"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI("node")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, err := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=? WHERE id='node'", identity.Fingerprint(c)); err != nil {
		t.Fatal(err)
	}
	if task, err := s.Poll(t.Context(), c); err != nil || task != nil {
		t.Fatal("monitoring unexpectedly enabled", task, err)
	}
	manual, err := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.ProcessList, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	poll := func() *protocol.Task {
		t.Helper()
		v, e := s.PollWithMonitoring(t.Context(), c, true)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	finish := func(v *protocol.Task) {
		t.Helper()
		if e := s.SubmitResult(t.Context(), c, protocol.NewResult(*v, protocol.Failed, "policy_denied")); e != nil {
			t.Fatal(e)
		}
	}
	if v := poll(); v.ID != manual.ID {
		t.Fatal("monitoring displaced manual work")
	} else {
		finish(v)
	}
	info := poll()
	if info.Type != protocol.SystemInfo {
		t.Fatal(info)
	}
	if retry := poll(); retry.ID != info.ID {
		t.Fatal("duplicate task", retry)
	}
	finish(info)
	metrics := poll()
	if metrics.Type != protocol.SystemMetrics {
		t.Fatal(metrics)
	}
	finish(metrics)
	if v := poll(); v != nil {
		t.Fatal("busy-loop on denied tasks", v)
	}
	now = now.Add(59 * time.Second)
	if v := poll(); v != nil {
		t.Fatal(v)
	}
	now = now.Add(time.Second)
	if v := poll(); v == nil || v.Type != protocol.SystemMetrics {
		t.Fatal(v)
	}
	if err = s.Disable(t.Context(), "admin", "node"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PollWithMonitoring(t.Context(), c, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("disabled node received work", err)
	}
}
