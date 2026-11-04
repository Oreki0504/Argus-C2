package policy

import (
	"encoding/json"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
)

func TestLocalOptInAndResourceBoundaries(t *testing.T) {
	p := Default()
	job := protocol.Task{Type: protocol.ServiceStatus, Params: json.RawMessage(`{"service_id":"ssh"}`)}
	if p.Allows(job) {
		t.Fatal("service enabled by default")
	}
	p.Allowed = append(p.Allowed, protocol.ServiceStatus)
	if p.Allows(job) {
		t.Fatal("unmapped resource allowed")
	}
	p.Services = []resources.Service{{ID: "ssh", Unit: "sshd.service"}}
	if !p.Allows(job) {
		t.Fatal("mapped service rejected")
	}
	job.Params = json.RawMessage(`{"service_id":"other"}`)
	if p.Allows(job) {
		t.Fatal("unknown resource accepted")
	}
	b, _ := json.Marshal(p)
	if _, e := Decode(b); e != nil {
		t.Fatal(e)
	}
	p.Services[0].Unit = "*.service"
	if p.Validate() == nil {
		t.Fatal("wildcard unit accepted")
	}
}
