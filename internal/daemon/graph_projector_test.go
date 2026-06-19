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
	mu       sync.Mutex
	hosts    map[string][]brain.HostSnapshot
	findings map[string][]brain.FindingSnapshot
}

func newFakeGraphWriter() *fakeGraphWriter {
	return &fakeGraphWriter{hosts: map[string][]brain.HostSnapshot{}, findings: map[string][]brain.FindingSnapshot{}}
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
	reg.For("globex").Submit(brain.HostObserved{ScopeID: "m9", Address: "192.168.1.1", OpenPorts: []int{443}})

	// Wait for the engines to fold the observations into their Worlds.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Hosts()) == 1 && len(reg.For("acme").Findings()) == 1 && len(reg.For("globex").Hosts()) == 1 {
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
}
