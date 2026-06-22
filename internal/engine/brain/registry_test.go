package brain

import (
	"context"
	"testing"
	"time"
)

// waitFor polls cond until true or the deadline, to assert on the registry's
// async tick loops without racing them (reads are read-locked).
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

// TestRegistry_PerTenantIsolation: For returns the same engine per tenant and
// distinct engines across tenants; each tenant's live World sees only its own
// events (no cross-tenant anything), read concurrently with the tick loops.
func TestRegistry_PerTenantIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewRegistry(ctx)

	if r.For("a") != r.For("a") {
		t.Fatal("For(a) returned different engines")
	}
	if r.For("a") == r.For("b") {
		t.Fatal("For(a) and For(b) returned the same engine")
	}

	r.For("a").Submit(HostObserved{ScopeID: "s", Address: "10.0.0.1", OpenPorts: []int{22}})
	r.For("b").Submit(HostObserved{ScopeID: "s", Address: "10.0.0.2", OpenPorts: []int{80}})

	waitFor(t, func() bool { return len(r.For("a").Hosts()) == 1 && len(r.For("b").Hosts()) == 1 })

	a, b := r.For("a").Hosts(), r.For("b").Hosts()
	if a[0].Address != "10.0.0.1" || b[0].Address != "10.0.0.2" {
		t.Fatalf("tenant worlds wrong: a=%+v b=%+v", a, b)
	}
	// Isolation: a never sees b's host and vice versa.
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("cross-tenant leak: a=%+v b=%+v", a, b)
	}

	if got := r.Tenants(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Tenants() = %v, want [a b]", got)
	}
}

// TestRegistry_LiveSystemsRun: systems installed on the registry run on each
// tenant's engine (here the belief system scores a submitted host).
func TestRegistry_LiveSystemsRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewRegistry(ctx, BeliefSystem(PlaceholderBeliefProvider()))

	r.For("a").Submit(HostObserved{ScopeID: "s", Address: "10.0.0.1", OpenPorts: []int{22, 80}})
	waitFor(t, func() bool {
		h := r.For("a").Hosts()
		return len(h) == 1 && h[0].Belief.Model == "placeholder-v0"
	})
}
