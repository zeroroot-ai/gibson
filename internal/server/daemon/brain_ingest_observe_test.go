// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// observeHost builds a host observation. Note what it cannot express: no tenant
// and no scope — those reach the sink only through ObservationAttribution, which
// the callback service fills from the daemon's mission record.
func observeHost(address, sshHostKey string) *harnesspb.ObserveRequest {
	return &harnesspb.ObserveRequest{
		Observation: &harnesspb.ObserveRequest_Host{
			Host: &harnesspb.HostObservation{Address: address, SshHostKey: sshHostKey},
		},
	}
}

// awaitHosts polls a tenant's World until it holds want hosts, then returns
// them. Fails the test on timeout, naming what it did see.
func awaitHosts(t *testing.T, reg *brain.Registry, tenant string, want int) []brain.HostSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var hosts []brain.HostSnapshot
	for time.Now().Before(deadline) {
		hosts = reg.For(tenant).Hosts()
		if len(hosts) == want {
			return hosts
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tenant %q: want %d hosts, got %d: %+v", tenant, want, len(hosts), hosts)
	return nil
}

// TestIngestObservation_SameAddressInDifferentScopesStaysDistinct is the
// identity property the whole server-side-scope design exists to protect.
//
// Host identity is the (ScopeID, Address) coordinate (ADR-0002). 10.0.0.1 on two
// separately-scanned customer networks is two hosts. If scope were derivable
// from the payload — or defaulted to "" when unresolvable — an agent could merge
// one customer's host record into another's by naming their coordinate, and the
// two networks would silently become one.
//
// This is the case worth more than any number of happy paths, so it also checks
// the converse: the same address in the SAME scope must merge, or "distinct"
// would be true for a trivial reason (every observation making a new entity).
func TestIngestObservation_SameAddressInDifferentScopesStaysDistinct(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	sink := ingestObservation(reg)

	attrFor := func(scope string) harness.ObservationAttribution {
		return harness.ObservationAttribution{Tenant: "acme", ScopeID: scope, MissionID: "mission-A"}
	}

	// Same address, two scanned networks.
	if err := sink(ctx, attrFor("target-net-a"), observeHost("10.0.0.1", "")); err != nil {
		t.Fatalf("sink net-a: %v", err)
	}
	if err := sink(ctx, attrFor("target-net-b"), observeHost("10.0.0.1", "")); err != nil {
		t.Fatalf("sink net-b: %v", err)
	}

	hosts := awaitHosts(t, reg, "acme", 2)
	scopes := map[string]string{}
	for _, h := range hosts {
		if h.Address != "10.0.0.1" {
			t.Fatalf("unexpected address %q", h.Address)
		}
		scopes[h.ScopeID] = h.Address
	}
	if len(scopes) != 2 {
		t.Fatalf("want two distinct scopes, got %v", scopes)
	}
	if _, ok := scopes["target-net-a"]; !ok {
		t.Fatalf("missing target-net-a: %v", scopes)
	}
	if _, ok := scopes["target-net-b"]; !ok {
		t.Fatalf("missing target-net-b: %v", scopes)
	}

	// Converse: re-observing the same coordinate in the SAME scope must resolve
	// to the existing entity, not create a third. Without this, "two hosts" above
	// would be satisfied by an implementation that never merges anything.
	if err := sink(ctx, attrFor("target-net-a"), observeHost("10.0.0.1", "")); err != nil {
		t.Fatalf("sink net-a repeat: %v", err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := len(reg.For("acme").Hosts()); n != 2 {
			t.Fatalf("re-observing the same (scope, address) must merge; got %d hosts", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestIngestObservation_RoutesToTheAttributedTenant: the sink writes into the
// World named by the attribution and nowhere else.
//
// It used to close over one process-wide tenant (d.registryTenant, defaulting to
// "default"), so every tenant's observations landed in a single shared World
// regardless of who emitted them. The registry no longer supplies a tenant at
// construction — there is nothing left for the sink to fall back to.
func TestIngestObservation_RoutesToTheAttributedTenant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	sink := ingestObservation(reg)

	err := sink(ctx, harness.ObservationAttribution{
		Tenant: "acme", ScopeID: "target-net-a", MissionID: "mission-A",
	}, observeHost("10.0.0.1", "ssh-ed25519 AAAA"))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	hosts := awaitHosts(t, reg, "acme", 1)
	if hosts[0].ScopeID != "target-net-a" {
		t.Fatalf("scope not carried through: %+v", hosts[0])
	}

	// No other tenant's World was touched — including the "default" namespace the
	// old wiring would have used.
	for _, other := range []string{"default", "evilcorp"} {
		if got := reg.For(other).Hosts(); len(got) != 0 {
			t.Fatalf("tenant %q saw acme's host: %+v", other, got)
		}
	}
}

// TestIngestObservation_CarriesMissionAttribution: the discovered host records
// the mission it was found by, so the write stays attributable to a mission a
// user launched, and the mission id is kept distinct from the scope.
func TestIngestObservation_CarriesMissionAttribution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	sink := ingestObservation(reg)

	err := sink(ctx, harness.ObservationAttribution{
		Tenant: "acme", ScopeID: "target-net-a", MissionID: "mission-A",
	}, observeHost("10.0.0.2", ""))
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	hosts := awaitHosts(t, reg, "acme", 1)
	if hosts[0].MissionID != "mission-A" {
		t.Fatalf("mission attribution lost: %+v", hosts[0])
	}
	if hosts[0].ScopeID == hosts[0].MissionID {
		t.Fatalf("scope and mission must stay distinct concepts: %+v", hosts[0])
	}
}
