package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/pki"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/probe"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/server"
	"github.com/Oreki0504/Argus-C2/internal/state"
	"github.com/Oreki0504/Argus-C2/internal/tlsconfig"
)

func requirePKI(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func readPKI(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	requirePKI(t, err)
	return b
}

func operationalPKI(t *testing.T, dir string) (tlsconfig.Files, *enrollment.Issuer) {
	t.Helper()
	requirePKI(t, os.Mkdir(dir, 0700))
	root := filepath.Join(dir, "offline-root")
	requirePKI(t, pki.CreateRoot(root, 0))
	ca, key := filepath.Join(root, "root-cert.pem"), filepath.Join(root, "root-key.pem")
	for _, profile := range []string{"server", "issuer"} {
		req, out := filepath.Join(dir, profile+"-request"), filepath.Join(dir, profile+"-issued")
		requirePKI(t, pki.PrepareRequest(req))
		_, err := pki.Issue(ca, key, filepath.Join(req, "request.pem"), profile, out, 0)
		requirePKI(t, err)
	}
	issuer, err := enrollment.LoadIssuer(filepath.Join(dir, "issuer-issued", "certificate.pem"), filepath.Join(dir, "issuer-request", "key.pem"), ca)
	requirePKI(t, err)
	requirePKI(t, issuer.SetLifetime(30*24*time.Hour))
	return tlsconfig.Files{Certificate: filepath.Join(dir, "server-issued", "certificate.pem"), PrivateKey: filepath.Join(dir, "server-request", "key.pem"), CA: ca}, issuer
}

func TestLocalRootReplacementPreservesIdentityAndPendingResult(t *testing.T) {
	dir := t.TempDir()
	oldServer, oldIssuer := operationalPKI(t, filepath.Join(dir, "old"))
	newServer, newIssuer := operationalPKI(t, filepath.Join(dir, "new"))
	store, err := state.Open(filepath.Join(dir, "state"))
	requirePKI(t, err)
	defer store.Close()
	et, err := tlsconfig.EnrollmentServer(oldServer)
	requirePKI(t, err)
	es := start(t, et, enrollment.Handler(store, oldIssuer))
	token, err := store.IssueToken(t.Context(), time.Minute)
	requirePKI(t, err)
	clientDir := filepath.Join(dir, "client")
	node, err := agent.Enroll(t.Context(), es.URL, oldServer.CA, token, clientDir)
	requirePKI(t, err)
	oldFiles := tlsconfig.Files{Certificate: filepath.Join(clientDir, "probe-cert.pem"), PrivateKey: filepath.Join(clientDir, "probe-key.pem"), CA: oldServer.CA}
	clientTLS, err := tlsconfig.Client(oldFiles, node, "127.0.0.1")
	requirePKI(t, err)
	pub, taskKey, err := ed25519.GenerateKey(rand.Reader)
	requirePKI(t, err)
	tasks, err := server.NewTaskService(t.Context(), store, taskKey)
	requirePKI(t, err)
	sc, err := tlsconfig.Server(oldServer, store)
	requirePKI(t, err)
	oldEndpoint := start(t, sc, server.Handler(store, tasks))
	c, err := agent.NewClient(oldEndpoint.URL, clientTLS, node)
	requirePKI(t, err)
	defer c.Close()

	policyBytes := readPKI(t, "../../examples/task-policy.json")
	p, err := policy.Decode(policyBytes)
	requirePKI(t, err)
	p.Telemetry.SampleMilliseconds = 100
	policyBytes, err = json.Marshal(p)
	requirePKI(t, err)
	policyPath := filepath.Join(dir, "policy.json")
	requirePKI(t, os.WriteFile(policyPath, policyBytes, 0600))
	replay := filepath.Join(dir, "replay")
	requirePKI(t, probe.Initialize(replay, node, pub))
	worker, err := probe.Open(replay, node, pub)
	requirePKI(t, err)
	defer func() {
		if worker != nil {
			worker.Close()
		}
	}()
	h := collectHeartbeat(t, node)
	h.Version = 2
	h.PolicyDigest, err = p.Digest()
	requirePKI(t, err)
	h.TaskState = "ready"
	requirePKI(t, c.Heartbeat(t.Context(), h))
	task, err := store.Enqueue(t.Context(), node.AgentID, protocol.SystemInfo, "test", time.Minute)
	requirePKI(t, err)
	wire, err := c.Poll(t.Context(), h.PolicyDigest)
	requirePKI(t, err)
	result, err := probe.NewEngine(worker, policyPath, oldEndpoint.URL).Process(t.Context(), wire)
	requirePKI(t, err)
	requirePKI(t, worker.Close())
	worker = nil

	// Trusted local preparation installs both public roots before switching the
	// server leaf and online issuer. No protocol response distributes trust.
	dualPath := filepath.Join(dir, "dual-ca.pem")
	requirePKI(t, os.WriteFile(dualPath, append(readPKI(t, oldServer.CA), readPKI(t, newServer.CA)...), 0600))
	newRoot := newServer.CA
	newServer.CA = dualPath
	sc, err = tlsconfig.Server(newServer, store)
	requirePKI(t, err)
	dualEndpoint := start(t, sc, server.HandlerWithRenewal(store, enrollment.RenewalHandler(store, newIssuer), tasks))
	oldFiles.CA = dualPath
	stage := filepath.Join(dir, "renewal")
	requirePKI(t, agent.PrepareRenewal(dualEndpoint.URL, oldFiles, node, stage))
	renewed, err := agent.RequestRenewal(t.Context(), dualEndpoint.URL, oldFiles, node, stage)
	requirePKI(t, err)
	again, err := agent.RequestRenewal(t.Context(), dualEndpoint.URL, oldFiles, node, stage)
	requirePKI(t, err)
	if renewed != again {
		t.Fatal("root transition changed idempotent issuance")
	}
	got, err := identity.LoadNode(filepath.Join(stage, "identity.json"))
	requirePKI(t, err)
	if got != node {
		t.Fatal("root transition changed node or epoch")
	}
	newFiles := tlsconfig.Files{Certificate: filepath.Join(stage, "probe-cert.pem"), PrivateKey: filepath.Join(stage, "probe-key.pem"), CA: newRoot}
	health, err := tlsconfig.Inspect(newFiles, tlsconfig.HealthOptions{Profile: "client", Node: &node})
	requirePKI(t, err)
	if health.State != "ok" {
		t.Fatal(health)
	}

	// Retire the old root locally on both ends and restart the affected
	// listeners/clients so established sessions cannot retain the old trust.
	dualEndpoint.Close()
	newServer.CA = newRoot
	sc, err = tlsconfig.Server(newServer, store)
	requirePKI(t, err)
	finalEndpoint := start(t, sc, server.Handler(store, tasks))
	cc, err := tlsconfig.Client(newFiles, node, "127.0.0.1")
	requirePKI(t, err)
	next, err := agent.NewClient(finalEndpoint.URL, cc, node)
	requirePKI(t, err)
	defer next.Close()
	_, err = next.Connect(t.Context())
	requirePKI(t, err)
	reject := func(url string, files tlsconfig.Files, n identity.Node) {
		t.Helper()
		cfg, err := tlsconfig.Client(files, n, "127.0.0.1")
		requirePKI(t, err)
		client, err := agent.NewClient(url, cfg, n)
		requirePKI(t, err)
		defer client.Close()
		if _, err := client.Connect(t.Context()); err == nil {
			t.Fatal("retired or unregistered authority accepted")
		}
	}
	oldFiles.CA = newRoot
	reject(finalEndpoint.URL, oldFiles, node) // Retired client root.
	reject(oldEndpoint.URL, newFiles, node)   // Retired server root.
	staleTrust := newFiles
	staleTrust.CA = oldServer.CA
	reject(finalEndpoint.URL, staleTrust, node) // Offline client missed local update.

	// A valid new-root certificate alone must not bypass the registry.
	rogueDir := filepath.Join(dir, "unregistered")
	requirePKI(t, pki.PrepareRequest(rogueDir))
	csr, err := pki.LoadRequest(filepath.Join(rogueDir, "request.pem"))
	requirePKI(t, err)
	rogueNode := identity.New()
	chain, _, err := newIssuer.Issue(csr, rogueNode)
	requirePKI(t, err)
	rogueCert := filepath.Join(rogueDir, "certificate.pem")
	requirePKI(t, os.WriteFile(rogueCert, chain, 0600))
	reject(finalEndpoint.URL, tlsconfig.Files{Certificate: rogueCert, PrivateKey: filepath.Join(rogueDir, "key.pem"), CA: newRoot}, rogueNode)

	worker, err = probe.Open(replay, node, pub)
	requirePKI(t, err)
	cached, err := probe.NewEngine(worker, policyPath, finalEndpoint.URL).Process(t.Context(), wire)
	requirePKI(t, err)
	if !bytes.Equal(cached, result) {
		t.Fatal("root transition changed cached result")
	}
	ack, err := next.SubmitResult(t.Context(), cached)
	requirePKI(t, err)
	if ack.RequestID != task.RequestID {
		t.Fatal("wrong pending-result acknowledgment")
	}
	requirePKI(t, worker.Acknowledge(t.Context(), ack.RequestID, ack.ResultDigest))
	audit, err := probe.ReadAudit(t.Context(), replay, 0, 100)
	requirePKI(t, err)
	admitted := 0
	for _, record := range audit.Records {
		if record.Event.Kind == "task_accepted" && record.Event.RequestID == task.RequestID {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatal("root transition repeated task execution", admitted)
	}
}
