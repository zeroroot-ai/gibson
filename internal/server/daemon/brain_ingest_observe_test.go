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
// Host identity is the (ScopeID, Address) coordinate (ADR-0102). 10.0.0.1 on two
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

// observeHypothesis builds a hypothesis observation (sdk#70, ADR-0121). Note
// what it cannot express: no tenant, no scope, no mission id — those reach
// the sink only through ObservationAttribution, exactly like every other
// observation kind.
func observeHypothesis(proposer, claim string, confidence float64, refs ...*harnesspb.ReferencedEntity) *harnesspb.ObserveRequest {
	return &harnesspb.ObserveRequest{
		Observation: &harnesspb.ObserveRequest_Hypothesis{
			Hypothesis: &harnesspb.HypothesisObservation{
				Proposer:   proposer,
				Confidence: confidence,
				Claim:      claim,
				References: refs,
			},
		},
	}
}

// awaitHypotheses polls a tenant's World until it holds want hypotheses, then
// returns them.
func awaitHypotheses(t *testing.T, reg *brain.Registry, tenant string, want int) []brain.HypothesisSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got []brain.HypothesisSnapshot
	for time.Now().Before(deadline) {
		got = reg.For(tenant).Hypotheses()
		if len(got) == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tenant %q: want %d hypotheses, got %d: %+v", tenant, want, len(got), got)
	return nil
}

// TestIngestObservation_Hypothesis proves a HypothesisObservation (ADR-0121)
// folds through the same Observe -> reducer path as every Evidence kind,
// lands as a Hypothesis (never a Host, never a Belief), and carries its
// references through the wire-to-brain translation.
func TestIngestObservation_Hypothesis(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	sink := ingestObservation(reg)

	req := observeHypothesis("recon-agent", "port 6443 is unauthenticated", 0.75,
		&harnesspb.ReferencedEntity{Label: "Host", IdProperties: map[string]string{"address": "10.0.0.1"}},
	)
	if err := sink(ctx, harness.ObservationAttribution{
		Tenant: "acme", ScopeID: "target-net-a", MissionID: "mission-A", RunID: "run-A",
	}, req); err != nil {
		t.Fatalf("sink: %v", err)
	}

	got := awaitHypotheses(t, reg, "acme", 1)
	h := got[0]
	if h.Claim != "port 6443 is unauthenticated" {
		t.Fatalf("claim lost in translation: %+v", h)
	}
	if h.Proposer != "recon-agent" {
		t.Fatalf("proposer lost in translation: %+v", h)
	}
	if h.Confidence != 0.75 {
		t.Fatalf("confidence lost in translation: %+v", h)
	}
	if h.ScopeID != "target-net-a" || h.MissionID != "mission-A" {
		t.Fatalf("attribution lost in translation: %+v", h)
	}
	// RunID is server-resolved off ObservationAttribution (gibson#339's
	// transcript-linking need), the same way MissionID is.
	if h.RunID != "run-A" {
		t.Fatalf("run id lost in translation: %+v", h)
	}
	if len(h.References) != 1 || h.References[0].Label != "Host" || h.References[0].IDProperties["address"] != "10.0.0.1" {
		t.Fatalf("references lost in translation: %+v", h)
	}

	// The Hypothesis provenance class never creates a Host, even though its
	// claim is about one (ADR-0121: a Hypothesis never sets Belief, and it
	// is folded entirely separately from Evidence).
	if hosts := reg.For("acme").Hosts(); len(hosts) != 0 {
		t.Fatalf("a hypothesis must never create a Host: %+v", hosts)
	}
}

// TestIngestObservation_Hypothesis_HypothesisIDAndTechnique proves
// HypothesisObservation.hypothesis_id and .technique (sdk#89/#88, wired now
// that go.mod pins an SDK release that carries them) survive the
// wire-to-brain translation into brain.Hypothesis — the join key gibson#339's
// ListOpenBets needs, and the reputation-keying signal gibson#333/#284 need,
// neither silently dropped.
func TestIngestObservation_Hypothesis_HypothesisIDAndTechnique(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	sink := ingestObservation(reg)

	req := &harnesspb.ObserveRequest{
		Observation: &harnesspb.ObserveRequest_Hypothesis{
			Hypothesis: &harnesspb.HypothesisObservation{
				Proposer:     "recon-agent",
				Confidence:   0.75,
				Claim:        "port 6443 is unauthenticated",
				HypothesisId: "hyp-6443",
				Technique:    "unauthenticated-service-probe",
			},
		},
	}
	if err := sink(ctx, harness.ObservationAttribution{
		Tenant: "acme", ScopeID: "target-net-a", MissionID: "mission-A", RunID: "run-A",
	}, req); err != nil {
		t.Fatalf("sink: %v", err)
	}

	got := awaitHypotheses(t, reg, "acme", 1)
	h := got[0]
	if h.HypothesisID != "hyp-6443" {
		t.Fatalf("hypothesis id lost in translation: %+v", h)
	}
	if h.Technique != "unauthenticated-service-probe" {
		t.Fatalf("technique lost in translation: %+v", h)
	}
}

// TestIngestObservation_Hypothesis_SameClaimInDifferentTenantsStaysDistinct
// proves tenant isolation holds for hypotheses the same way it does for
// hosts: each tenant has its own World (ADR-0101), so an identical claim
// proposed under two tenants is two hypotheses, one per World, never one
// record leaking across the tenant boundary.
func TestIngestObservation_Hypothesis_SameClaimInDifferentTenantsStaysDistinct(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	sink := ingestObservation(reg)

	req := observeHypothesis("recon-agent", "shared claim text", 0.5)
	if err := sink(ctx, harness.ObservationAttribution{Tenant: "acme", ScopeID: "s1", MissionID: "m1"}, req); err != nil {
		t.Fatalf("sink acme: %v", err)
	}
	if err := sink(ctx, harness.ObservationAttribution{Tenant: "globex", ScopeID: "s1", MissionID: "m1"}, req); err != nil {
		t.Fatalf("sink globex: %v", err)
	}

	awaitHypotheses(t, reg, "acme", 1)
	awaitHypotheses(t, reg, "globex", 1)
}
