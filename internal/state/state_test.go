package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/devpki"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}
func registration() identity.Registration {
	n := identity.New()
	return identity.Registration{AgentID: n.AgentID, EnrollmentEpoch: n.EnrollmentEpoch, CertificateSHA256: identity.RandomID() + identity.RandomID(), Enabled: true}
}
func issue(t *testing.T, s *Store) string {
	t.Helper()
	token, err := s.IssueToken(context.Background(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestTokenAtomicAcrossConnectionsAndRestart(t *testing.T) {
	s, dir := openTest(t)
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	token := issue(t, s)
	var digest string
	if err := s.db.QueryRow("SELECT token_hash FROM enrollment_tokens").Scan(&digest); err != nil {
		t.Fatal(err)
	}
	want, _ := tokenHash(token)
	if digest != want || digest == token {
		t.Fatal("token was not hashed")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for j := 0; j < 24; j++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := s
			if i%2 == 0 {
				db = other
			}
			err := db.Register(context.Background(), token, registration())
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("unexpected registration failure: %v", err)
			}
		}(j)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("got %d registrations", successes.Load())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Register(context.Background(), token, registration()); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("token reused after restart", err)
	}
	nodes, err := reopened.Snapshots(context.Background())
	if err != nil || len(nodes) != 1 {
		t.Fatal("registration lost", nodes, err)
	}
}

func TestExpiryRollbackAndSchema(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	for _, ttl := range []time.Duration{0, 16 * time.Minute} {
		if _, err := s.IssueToken(ctx, ttl); err == nil {
			t.Fatal("accepted invalid lifetime")
		}
	}
	token := issue(t, s)
	if _, err := s.db.Exec("UPDATE enrollment_tokens SET expires_at=?", time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ctx, token, registration()); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired token accepted", err)
	}
	r := registration()
	token = issue(t, s)
	if err := s.Register(ctx, token, r); err != nil {
		t.Fatal(err)
	}
	retry := issue(t, s)
	if err := s.Register(ctx, retry, r); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	if err := s.Register(ctx, retry, registration()); err != nil {
		t.Fatal("rollback consumed token", err)
	}
	if _, err := s.db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if unknown, err := Open(dir); err == nil {
		unknown.Close()
		t.Fatal("unknown schema silently reset")
	}
}

func TestPersistentHeartbeatAndDisable(t *testing.T) {
	s, dir := openTest(t)
	ctx := context.Background()
	b, err := devpki.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ctx, issue(t, s), b.Registration()); err != nil {
		t.Fatal(err)
	}
	h := protocol.Heartbeat{Version: 1, AgentID: b.Node.AgentID, EnrollmentEpoch: b.Node.EnrollmentEpoch, SentAt: time.Now().Unix(), Info: protocol.SystemInformation{OS: "linux", Architecture: "amd64"}, Metrics: protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}}}
	wrong := h
	wrong.AgentID = identity.RandomID()
	if err := s.SaveHeartbeat(ctx, b.Probe.Leaf, wrong); err == nil {
		t.Fatal("cross-node heartbeat accepted")
	}
	if err := s.SaveHeartbeat(ctx, b.Probe.Leaf, h); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHeartbeat(ctx, b.Probe.Leaf, h); !errors.Is(err, ErrRateLimited) {
		t.Fatal("heartbeat write budget missing", err)
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Disable(ctx, b.Node.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(b.Probe.Leaf); err == nil {
		t.Fatal("disablement was cached")
	}
	if err := s.SaveHeartbeat(ctx, b.Probe.Leaf, h); err == nil {
		t.Fatal("disabled node updated telemetry")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rows, err := reopened.Snapshots(ctx)
	if err != nil || len(rows) != 1 || rows[0].Enabled || rows[0].ReceivedAt == 0 {
		t.Fatal("persistent snapshot missing", rows, err)
	}
	if _, err := protocol.DecodeHeartbeat(rows[0].Heartbeat); err != nil {
		t.Fatal(err)
	}
}

func TestPrivatePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions and symlink behavior")
	}
	dir := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(dir); err == nil {
		s.Close()
		t.Fatal("public directory accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do not touch"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "argus.db")); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(dir); err == nil {
		s.Close()
		t.Fatal("database symlink accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(data), "do not touch") {
		t.Fatal("symlink target modified")
	}
}
