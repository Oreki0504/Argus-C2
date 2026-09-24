package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
	"golang.org/x/crypto/ssh"
)

func TestInspectionTasksOverMTLS(t *testing.T) {
	f := setupEnrollment(t)
	f.enroll(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	dispatcher, err := server.NewTaskService(t.Context(), f.store, key)
	if err != nil {
		t.Fatal(err)
	}
	pki := filepath.Join(f.root, "pki")
	config, err := tlsconfig.Server(tlsconfig.Files{Certificate: filepath.Join(pki, "server-cert.pem"), PrivateKey: filepath.Join(pki, "server-key.pem"), CA: f.ca}, f.store)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := start(t, config, server.Handler(f.store, dispatcher))
	client, err := agent.NewClient(endpoint.URL, f.clientTLS, f.node)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	b, err := os.ReadFile("../../examples/task-policy-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyLine := bytes.TrimSpace(ssh.MarshalAuthorizedKey(publicKey))
	keyData := append(append([]byte{}, keyLine...), []byte(" PRIVATE_COMMENT\n")...)
	hash := sha256.Sum256(keyData)
	resourceDir := t.TempDir()
	for name, data := range map[string][]byte{"authorized_keys": keyData, "sshd_config": []byte("PermitRootLogin no\nInclude /private/unmapped/*.conf\nMatch User private-user\nPermitRootLogin yes\n")} {
		if err := os.WriteFile(filepath.Join(resourceDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := resourceDir
	if runtime.GOOS != "linux" {
		base = "/unavailable/test-fixtures"
	}
	file := resources.SSHFile{ID: "keys", Kind: "authorized_keys", BaseDir: base, RelativePath: "authorized_keys", OwnerUID: uint32(os.Getuid()), OwnerGID: uint32(os.Getgid()), MaxBytes: 4096, BaselineSHA256: hex.EncodeToString(hash[:])}
	cfg := file
	cfg.ID = "config"
	cfg.Kind = "sshd_config"
	cfg.RelativePath = "sshd_config"
	cfg.BaselineSHA256 = ""
	missing := file
	missing.ID = "missing"
	missing.RelativePath = "authorized_keys2"
	missing.BaselineSHA256 = ""
	p.SSHProfiles = []resources.SSHProfile{{ID: "host", Files: []resources.SSHFile{file, cfg, missing}}}
	p.Services = []resources.Service{{ID: "journal", Unit: "systemd-journald.service"}}
	p.AllowSSHAudit = true
	p.AllowServiceStatus = true
	b, _ = json.Marshal(p)
	policyPath := filepath.Join(f.root, "inspection-policy.json")
	if err := os.WriteFile(policyPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.root, "inspection-state")
	if err := probe.Initialize(dir, f.node, pub); err != nil {
		t.Fatal(err)
	}
	worker, err := probe.Open(dir, f.node, pub)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	engine := probe.NewEngine(worker, policyPath, endpoint.URL)
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := protocol.Heartbeat{Version: 2, AgentID: f.node.AgentID, EnrollmentEpoch: f.node.EnrollmentEpoch, SentAt: time.Now().Unix(), Info: protocol.SystemInformation{OS: "test", Architecture: "test"}, Metrics: protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}}, PolicyDigest: digest, TaskState: "ready"}
	if err := client.Heartbeat(t.Context(), heartbeat); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind     protocol.TaskType
		params   string
		rejected bool
	}{
		{protocol.SSHAudit, `{"profile_id":"host"}`, false},
		{protocol.ServiceStatus, `{"service_id":"journal"}`, false},
		{protocol.SSHAudit, `{"profile_id":"unmapped"}`, true},
	} {
		task, err := f.store.Enqueue(t.Context(), f.node.AgentID, tc.kind, "integration", time.Minute, json.RawMessage(tc.params))
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := client.Poll(t.Context(), digest)
		if err != nil || len(envelope) == 0 {
			t.Fatal("missing dispatch", err)
		}
		data, err := engine.Process(t.Context(), envelope)
		if err != nil {
			t.Fatal(err)
		}
		r, err := protocol.DecodeResult(data)
		if err != nil || r.RequestID != task.RequestID {
			t.Fatal("invalid result", err)
		}
		if tc.rejected {
			if r.Status != protocol.Rejected || r.ErrorCode != "resource_denied" {
				t.Fatal(r)
			}
		} else {
			if r.Status != protocol.Succeeded {
				t.Fatal(r)
			}
			wrong := r
			if tc.kind == protocol.SSHAudit {
				report, err := protocol.DecodeSSHReport(r.Data, r.FinishedAt)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS == "linux" {
					if report.Coverage != "partial" || report.Files[0].Baseline != "match" || len(report.Files[0].Keys) != 1 || report.Files[0].Keys[0].Fingerprint != ssh.FingerprintSHA256(publicKey) || report.Files[1].Status != "partial" || len(report.Files[1].Directives) != 1 || report.Files[2].Status != "missing" {
						t.Fatal("wrong native observations", report)
					}
				} else if report.Coverage != "unavailable" || report.Files[0].Status != "unsupported" {
					t.Fatal(report)
				}
				for _, secret := range []string{"PRIVATE_COMMENT", strings.Fields(string(keyLine))[1], "/private/unmapped", "private-user"} {
					if bytes.Contains(data, []byte(secret)) {
						t.Fatal("raw file content escaped report")
					}
				}
				report.ProfileID = "another"
				wrong.Data, _ = json.Marshal(report)
			} else {
				report, err := protocol.DecodeServiceReport(r.Data, r.FinishedAt)
				if err != nil || report.ServiceID != "journal" {
					t.Fatal(report, err)
				}
				if runtime.GOOS != "linux" && (report.Available || report.Code != "unsupported") {
					t.Fatal(report)
				}
				report.ServiceID = "another"
				wrong.Data, _ = json.Marshal(report)
			}
			wrongBytes, _ := json.Marshal(wrong)
			if _, err := client.SubmitResult(t.Context(), wrongBytes); err == nil {
				t.Fatal("cross-resource result accepted")
			}
		}
		ack, err := client.SubmitResult(t.Context(), data)
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.Acknowledge(t.Context(), ack.RequestID, ack.ResultDigest); err != nil {
			t.Fatal(err)
		}
		cached, err := engine.Process(t.Context(), envelope)
		if err != nil || !bytes.Equal(cached, data) {
			t.Fatal("inspection replay changed", err)
		}
	}
	rows, err := f.store.Tasks(t.Context(), 0, 100)
	if err != nil || len(rows) != 3 || rows[2].State != "rejected" {
		t.Fatal(rows, err)
	}
	if _, err := probe.ReadAudit(t.Context(), dir, 0, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Audit(t.Context(), 0, 100); err != nil {
		t.Fatal(err)
	}
}
