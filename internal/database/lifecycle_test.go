package database

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func lifecycleCertificate(t *testing.T, s *Store) *x509.Certificate {
	t.Helper()
	now := time.Now()
	c := &x509.Certificate{Raw: []byte("lifecycle"), URIs: []*url.URL{identity.URI("node")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, err := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=?", identity.Fingerprint(c)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSuccessRequiresDurableExecutionGrant(t *testing.T) {
	for _, grant := range []bool{false, true} {
		t.Run(map[bool]string{false: "never-authorized", true: "authorized"}[grant], func(t *testing.T) {
			s := fixture(t)
			c := lifecycleCertificate(t, s)
			now := time.Now().Truncate(time.Second)
			s.clock = func() time.Time { return now }
			job, err := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: json.RawMessage(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 1000})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Poll(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			r := protocol.NewResult(job, protocol.Succeeded, "")
			r.Payload = json.RawMessage(`{"available":false,"os":"linux","architecture":"amd64","hostname":"","kernel":"","boot_time":0}`)
			if err = s.SubmitResult(t.Context(), c, r); !errors.Is(err, ErrTaskRejected) {
				t.Fatal("ACCEPTED success bypassed grant", err)
			}
			if grant {
				if err = s.Running(t.Context(), c, job.ID); err != nil {
					t.Fatal(err)
				}
			}
			now = now.Add(2 * time.Minute)
			v, err := s.Task(t.Context(), job.ID)
			if err != nil || v.Task.Status != protocol.Unknown || v.Result != nil {
				t.Fatal(v, err)
			}
			err = s.SubmitResult(t.Context(), c, r)
			if grant {
				if err != nil {
					t.Fatal("authorized late success rejected", err)
				}
				v, err = s.Task(t.Context(), job.ID)
				if err != nil || v.ExecutionAuthorizedAt == 0 || v.ResultReceivedAt != now.Unix() {
					t.Fatal(v, err)
				}
			} else {
				if !errors.Is(err, ErrTaskRejected) {
					t.Fatal("UNKNOWN success bypassed grant", err)
				}
				if err = s.SubmitResult(t.Context(), c, protocol.NewResult(job, protocol.Failed, "local_policy_denied")); err != nil {
					t.Fatal("legitimate local rejection blocked", err)
				}
			}
		})
	}
}

func TestReceiptTimeProtectsLateResultsAndCannotBeRefreshed(t *testing.T) {
	for _, future := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-completion", true: "future-completion"}[future], func(t *testing.T) {
			s := fixture(t)
			c := lifecycleCertificate(t, s)
			now := time.Now().Truncate(time.Second)
			s.clock = func() time.Time { return now }
			seedHistory(t, s, "delayed", protocol.Unknown, now.Add(-35*24*time.Hour).Unix(), false)
			r := protocol.Result{TaskID: "delayed", NodeID: "node", Status: protocol.Failed, Payload: json.RawMessage(`{}`), Error: "collector_timeout", CompletedAt: now.Add(-35 * 24 * time.Hour).Unix()}
			if future {
				r.CompletedAt = now.Add(365 * 24 * time.Hour).Unix()
			}
			if err := s.SubmitResult(t.Context(), c, r); err != nil {
				t.Fatal(err)
			}
			received := now.Unix()
			p, err := s.PreviewPrune(t.Context(), 30, 90, 200)
			if err != nil || len(p.Items) != 0 {
				t.Fatal("new receipt eligible", p, err)
			}
			now = now.Add(30 * 24 * time.Hour)
			if err = s.SubmitResult(t.Context(), c, r); err != nil {
				t.Fatal(err)
			}
			v, err := s.Task(t.Context(), r.TaskID)
			if err != nil || v.ResultReceivedAt != received {
				t.Fatal("retry refreshed receipt", v, err)
			}
			p, err = s.PreviewPrune(t.Context(), 30, 90, 200)
			if err != nil || len(p.Items) != 0 {
				t.Fatal("exact boundary pruned", p, err)
			}
			now = now.Add(time.Second)
			p, err = s.Prune(t.Context(), 30, 90, 200, filepath.Join(t.TempDir(), "snapshot.db"))
			if err != nil || p.Deleted != 1 {
				t.Fatal("completion time controlled retention", p, err)
			}
		})
	}
}

func TestUnknownRetentionAndLateArrivalInvalidateFrozenBatch(t *testing.T) {
	s := fixture(t)
	c := lifecycleCertificate(t, s)
	now := time.Now().Truncate(time.Second)
	s.clock = func() time.Time { return now }
	cutoff := now.Add(-90 * 24 * time.Hour).Unix()
	seedHistory(t, s, "old-unknown", protocol.Unknown, cutoff-1, false)
	seedHistory(t, s, "boundary", protocol.Unknown, cutoff, false)
	p, err := s.PreviewPrune(t.Context(), 30, 90, 200)
	if err != nil || len(p.Items) != 1 || p.Items[0].HasResult {
		t.Fatal(p, err)
	}
	r := protocol.NewResult(protocol.Task{ID: "old-unknown", NodeID: "node"}, protocol.Unknown, "agent_interrupted")
	if err = s.SubmitResult(t.Context(), c, r); err != nil {
		t.Fatal(err)
	}
	if err = s.Write(t.Context(), func(tx *sql.Tx) error { return pruneBatch(t.Context(), tx, p) }); err == nil {
		t.Fatal("new result deleted by stale UNKNOWN candidate")
	}
	seedHistory(t, s, "discardable", protocol.Unknown, cutoff-1, false)
	p, err = s.Prune(t.Context(), 30, 90, 200, filepath.Join(t.TempDir(), "snapshot.db"))
	if err != nil || p.Deleted != 1 || p.Items[0].TaskID != "discardable" {
		t.Fatal(p, err)
	}
	r.TaskID = "discardable"
	if err = s.SubmitResult(t.Context(), c, r); !errors.Is(err, ErrTaskNotFound) {
		t.Fatal("pruned UNKNOWN upload acknowledged", err)
	}
}
