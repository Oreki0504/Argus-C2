package sshaudit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"golang.org/x/crypto/ssh"
)

func observation(kind string) protocol.SSHFileObservation {
	return protocol.SSHFileObservation{ID: "file", Kind: kind, Status: "ok", Keys: []protocol.KeyObservation{}, Directives: []protocol.DirectiveObservation{}, Findings: []string{}}
}
func publicLine(t *testing.T) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), ssh.FingerprintSHA256(k)
}
func TestKeyFingerprintsNeverReturnLinesCommentsOrOptions(t *testing.T) {
	line, fingerprint := publicLine(t)
	f := observation("authorized_keys")
	parse([]byte(`command="echo SECRET_COMMAND",from="SECRET_SOURCE" `+line+" SECRET_COMMENT\r\n"), &f)
	if f.Status != "partial" || len(f.Keys) != 1 || f.Keys[0].Fingerprint != fingerprint || !f.Keys[0].HasOptions {
		t.Fatal(f)
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "SECRET_") || strings.Contains(string(b), strings.Fields(line)[1]) {
		t.Fatal("raw key material escaped summary")
	}
	f = observation("authorized_keys")
	parse([]byte(line+"\nmalformed private data\n"+line), &f)
	if f.Status != "parse_error" || len(f.Keys) != 0 {
		t.Fatal("invalid line silently skipped", f)
	}
	f = observation("authorized_keys")
	parse([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n"), &f)
	if f.Status != "sensitive_content" || len(f.Keys) != 0 {
		t.Fatal(f)
	}
	f = observation("authorized_keys")
	parse([]byte(strings.Repeat(line+"\n", 9)), &f)
	if f.Status != "partial" || len(f.Keys) != 8 {
		t.Fatal("key limit", f)
	}
	f = observation("authorized_keys")
	parse([]byte(line+"\rmalformed"), &f)
	if f.Status != "parse_error" {
		t.Fatal("embedded carriage return accepted")
	}
}
func TestStaticConfigurationCoverage(t *testing.T) {
	f := observation("sshd_config")
	parse([]byte("PermitRootLogin no\nPasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User private-user\nPermitRootLogin yes\nAuthorizedKeysCommand /private/command --secret\n"), &f)
	if f.Status != "partial" || len(f.Directives) != 2 || f.Directives[0].Value != "no" {
		t.Fatal(f)
	}
	b, _ := json.Marshal(f)
	for _, secret := range []string{"private-user", "/private/command", "--secret", "/etc/ssh"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("raw config value escaped", secret)
		}
	}
	f = observation("sshd_config")
	parse([]byte("PasswordAuthentication yes\nPasswordAuthentication no\nUnknownKeyword secret\n"), &f)
	if f.Status != "partial" || len(f.Directives) != 1 || f.Directives[0].Value != "yes" {
		t.Fatal(f)
	}
	f = observation("sshd_config")
	parse([]byte("root:secret:0:0:root:/root:/bin/sh"), &f)
	if f.Status != "parse_error" {
		t.Fatal("non-config file accepted")
	}
}
func FuzzSSHParsers(f *testing.F) {
	f.Add([]byte("PermitRootLogin no\nMatch User example\nPasswordAuthentication yes\n"))
	f.Add([]byte("ssh-ed25519 invalid example"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		for _, kind := range []string{"sshd_config", "authorized_keys"} {
			o := observation(kind)
			parse(data, &o)
			if len(o.Keys) > 8 || len(o.Directives) > 8 || len(o.Findings) > 16 || !protocol.InspectionCode(o.Status) {
				t.Fatal("unbounded or invalid parser output")
			}
			for _, v := range o.Findings {
				if !protocol.SSHFinding(v) {
					t.Fatal("unregistered finding")
				}
			}
		}
	})
}
