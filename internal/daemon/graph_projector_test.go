package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/brain"
)

// fakeGraphWriter records UpsertHost calls per tenant for assertion.
type fakeGraphWriter struct {
	mu         sync.Mutex
	hosts      map[string][]brain.HostSnapshot
	findings   map[string][]brain.FindingSnapshot
	domains     map[string][]brain.DomainSnapshot
	subdomains  map[string][]brain.SubdomainSnapshot
	credentials map[string][]brain.CredentialSnapshot
	accounts    map[string][]brain.AccountSnapshot
}

func newFakeGraphWriter() *fakeGraphWriter {
	return &fakeGraphWriter{
		hosts:       map[string][]brain.HostSnapshot{},
		findings:    map[string][]brain.FindingSnapshot{},
		domains:     map[string][]brain.DomainSnapshot{},
		subdomains:  map[string][]brain.SubdomainSnapshot{},
		credentials: map[string][]brain.CredentialSnapshot{},
		accounts:    map[string][]brain.AccountSnapshot{},
	}
}

func (f *fakeGraphWriter) UpsertHost(_ context.Context, tenant string, h brain.HostSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts[tenant] = append(f.hosts[tenant], h)
	return nil
}

func (f *fakeGraphWriter) UpsertFinding(_ context.Context, tenant string, fn brain.FindingSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findings[tenant] = append(f.findings[tenant], fn)
	return nil
}

func (f *fakeGraphWriter) UpsertDomain(_ context.Context, tenant string, d brain.DomainSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domains[tenant] = append(f.domains[tenant], d)
	return nil
}

func (f *fakeGraphWriter) UpsertSubdomain(_ context.Context, tenant string, s brain.SubdomainSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subdomains[tenant] = append(f.subdomains[tenant], s)
	return nil
}

func (f *fakeGraphWriter) UpsertCredential(_ context.Context, tenant string, c brain.CredentialSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.credentials[tenant] = append(f.credentials[tenant], c)
	return nil
}

func (f *fakeGraphWriter) UpsertAccount(_ context.Context, tenant string, a brain.AccountSnapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[tenant] = append(f.accounts[tenant], a)
	return nil
}

// TestGraphProjector_ProjectsWorldPerTenant: the projector reads each tenant's
// World and upserts its hosts (ADR-0007), with strict per-tenant isolation and
// the host's stable id + service detail carried through to the writer.
func TestGraphProjector_ProjectsWorldPerTenant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)

	reg.For("acme").Submit(brain.HostObserved{
		ScopeID: "m1", Address: "10.0.0.5", SSHHostKey: "AAAA",
		OpenPorts: []int{22}, Services: map[int]brain.ServiceInfo{22: {Name: "ssh", Product: "OpenSSH"}},
	})
	reg.For("acme").Submit(brain.FindingRaised{
		ID: "f1", Title: "weak ssh", ScopeID: "m1", Address: "10.0.0.5", Severity: "high",
	})
	reg.For("acme").Submit(brain.DomainObserved{ScopeID: "m1", Name: "example.com"})
	reg.For("acme").Submit(brain.SubdomainObserved{ScopeID: "m1", FQDN: "api.example.com", Domain: "example.com", Addresses: []string{"10.0.0.5"}})
	reg.For("acme").Submit(brain.CredentialObserved{ScopeID: "m1", SecretHash: "deadbeef", Username: "root", CredentialKind: "ssh_key"})
	reg.For("acme").Submit(brain.AccountObserved{ScopeID: "m1", Identifier: "admin", AccountKind: "local"})
	reg.For("globex").Submit(brain.HostObserved{ScopeID: "m9", Address: "192.168.1.1", OpenPorts: []int{443}})

	// Wait for the engines to fold the observations into their Worlds.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a := reg.For("acme")
		if len(a.Hosts()) == 1 && len(a.Findings()) == 1 && len(a.Domains()) == 1 && len(a.Subdomains()) == 1 &&
			len(a.Credentials()) == 1 && len(a.Accounts()) == 1 && len(reg.For("globex").Hosts()) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	writer := newFakeGraphWriter()
	p := NewGraphProjector(reg, writer, time.Hour, nil)
	p.project(ctx)

	writer.mu.Lock()
	defer writer.mu.Unlock()

	if got := len(writer.hosts["acme"]); got != 1 {
		t.Fatalf("acme: projected %d hosts, want 1", got)
	}
	if got := len(writer.hosts["globex"]); got != 1 {
		t.Fatalf("globex: projected %d hosts, want 1", got)
	}
	// acme isolation: globex's host must not appear under acme.
	acme := writer.hosts["acme"][0]
	if acme.Address != "10.0.0.5" || acme.ID == 0 {
		t.Fatalf("acme host wrong/missing stable id: %+v", acme)
	}
	if svc, ok := acme.Services[22]; !ok || svc.Product != "OpenSSH" {
		t.Fatalf("acme host service detail not projected: %+v", acme.Services)
	}

	// Finding projected under acme only (isolation), carrying its host coordinate
	// so the writer can draw AFFECTS.
	if got := len(writer.findings["acme"]); got != 1 {
		t.Fatalf("acme: projected %d findings, want 1", got)
	}
	if got := len(writer.findings["globex"]); got != 0 {
		t.Fatalf("globex: projected %d findings, want 0 (isolation)", got)
	}
	if fn := writer.findings["acme"][0]; fn.ID != "f1" || fn.Address != "10.0.0.5" || fn.Severity != "high" {
		t.Fatalf("acme finding wrong: %+v", fn)
	}

	// Domain + subdomain projected under acme only.
	if got := len(writer.domains["acme"]); got != 1 || writer.domains["acme"][0].Name != "example.com" {
		t.Fatalf("acme domains wrong: %+v", writer.domains["acme"])
	}
	if got := len(writer.subdomains["acme"]); got != 1 {
		t.Fatalf("acme: projected %d subdomains, want 1", got)
	}
	if sd := writer.subdomains["acme"][0]; sd.FQDN != "api.example.com" || len(sd.Addresses) != 1 {
		t.Fatalf("acme subdomain wrong: %+v", sd)
	}
	if len(writer.domains["globex"]) != 0 {
		t.Fatalf("globex domain isolation breached: %+v", writer.domains["globex"])
	}

	// Credential + account projected under acme only.
	if got := len(writer.credentials["acme"]); got != 1 || writer.credentials["acme"][0].SecretHash != "deadbeef" {
		t.Fatalf("acme credentials wrong: %+v", writer.credentials["acme"])
	}
	if got := len(writer.accounts["acme"]); got != 1 || writer.accounts["acme"][0].Identifier != "admin" {
		t.Fatalf("acme accounts wrong: %+v", writer.accounts["acme"])
	}
	if len(writer.credentials["globex"]) != 0 || len(writer.accounts["globex"]) != 0 {
		t.Fatalf("globex credential/account isolation breached")
	}
}
