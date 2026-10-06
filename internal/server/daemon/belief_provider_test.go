// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TestDefaultBeliefSet_IsTheEmbeddedBaseModel proves that a tenant with no
// current version scores in-process against the OSS-embedded base-v1 model
// (ADR-0134) and grounds every slice on the cold-start prior (ADR-0137).
func TestDefaultBeliefSet_IsTheEmbeddedBaseModel(t *testing.T) {
	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	set, err := defaultBeliefSet(reg)
	if err != nil {
		t.Fatalf("defaultBeliefSet: %v", err)
	}
	if got := set.label(); got != "base-v1" {
		t.Fatalf("default label = %q, want base-v1", got)
	}
	if got := set.slice.Version(); got != "native-slice-v0-uninformative-prior" {
		t.Fatalf("default slice version = %q, want native-slice-v0-uninformative-prior", got)
	}
	if got, want := set.edges.Posterior("RESOLVES_TO"), (brain.UninformativeEdgePosteriors{}).Posterior("RESOLVES_TO"); got != want {
		t.Fatalf("default posterior = %+v, want the uninformative prior %+v", got, want)
	}
}

// TestStoredBeliefSet_UsesBothArtifacts proves that a stored version builds
// the belief model and the edge posteriors from its own two artifacts, and
// that the slice provider names the posterior version it grounds with.
func TestStoredBeliefSet_UsesBothArtifacts(t *testing.T) {
	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	set, err := storedBeliefSet(reg, 3, testBeliefModel("tenant-acme-v3"), testEdgePosteriors("tenant-acme-v3"))
	if err != nil {
		t.Fatalf("storedBeliefSet: %v", err)
	}
	if got := set.label(); got != "tenant-acme-v3" {
		t.Fatalf("label = %q, want tenant-acme-v3", got)
	}
	if got, want := set.slice.Version(), "native-slice-v0-uninformative-prior+edges:tenant-acme-v3"; got != want {
		t.Fatalf("slice version = %q, want %q", got, want)
	}
	if got := set.edges.Posterior("RESOLVES_TO").Mean(); got != 8.0/12.0 {
		t.Fatalf("RESOLVES_TO mean = %v, want %v", got, 8.0/12.0)
	}
}

// TestStoredBeliefSet_RefusesABadArtifact proves that a version whose
// artifact does not parse fails loudly instead of falling back to a
// different model.
func TestStoredBeliefSet_RefusesABadArtifact(t *testing.T) {
	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	if _, err := storedBeliefSet(reg, 1, []byte(`{"version":"x"}`), testEdgePosteriors("x")); err == nil {
		t.Fatal("expected an error for a belief model with no query variables")
	}
	if _, err := storedBeliefSet(reg, 1, testBeliefModel("x"), []byte(`{"posteriors":{}}`)); err == nil {
		t.Fatal("expected an error for edge posteriors with no version")
	}
}

// TestNewBeliefSchemaRegistry_RegistersTheCoreSeed proves the daemon's
// belief-schema registry is the real, shipped core seed (gibson#296) — Host
// belief-bearing with the reachable/exploitable/juicy funnel — not an empty
// or hand-rolled registry.
func TestNewBeliefSchemaRegistry_RegistersTheCoreSeed(t *testing.T) {
	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	if !reg.IsBeliefBearing("Host") {
		t.Fatalf("registry does not declare Host belief-bearing")
	}
	if !reg.IsEnablementEdge("RESOLVES_TO") {
		t.Fatalf("registry does not declare RESOLVES_TO an enablement edge")
	}
}

// TestWireBrainRegistry_InstallsBothBeliefPipelines proves wireBrainRegistry —
// the helper daemon.go's Start() and grpc.go's lazy fallback both call,
// replacing what used to be duplicated inline — actually installs a hook that
// runs both the per-host (WireBelief) and graph-coupled (WireSliceBelief,
// gibson#275) pipelines on every engine the registry creates. Registry.For
// starts the engine's own tick loop and runs the OnEngine hooks immediately,
// so a host observed on it gets a belief from ONE of the two pipelines within
// a couple of tick intervals — which one wins the race for Host.Belief.Model
// is not deterministic (both run on independent ~50ms tickers against the
// same field), so this asserts only that wiring is live, not an ordering.
func TestWireBrainRegistry_InstallsBothBeliefPipelines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := brain.NewRegistry(ctx, brain.BeliefSystem)
	beliefSchemaRegistry, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	wireBrainRegistry(ctx, registry, testTenantBeliefs(t, beliefSchemaRegistry, nil), beliefSchemaRegistry)

	e := registry.For("tenant-wire-test") // triggers the OnEngine hook
	e.Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hosts := e.Hosts()
		if len(hosts) == 1 && hosts[0].Belief.Model != "" {
			return // some pipeline scored it — wiring is live
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("host was never scored by either belief pipeline within the deadline")
}

// TestWireBrainRegistry_InstallsVoIPlanner proves wireBrainRegistry also
// installs value-of-information planning (ADR-0126, gibson#283) live: a
// running goal mission gets a completed VoI plan within a few ticks, the
// same way TestWireBrainRegistry_InstallsBothBeliefPipelines proves the
// belief pipelines. Before this wiring, VoIGateSystem/WireVoIPlanner were
// never installed on any engine the daemon constructs — the whole VoI
// subsystem was built but unreachable from daemon main() (the whole-program
// deadcode gate's finding at epic->main).
//
// The registry is constructed with brain.ExecutorSystems() (which
// VoIGateSystem joins), mirroring daemon.go's Start() exactly — not just
// brain.BeliefSystem alone, the way the belief-pipeline test above does —
// because VoIGateSystem's in-tick request is the other half VoIWorker's
// off-tick drain needs.
func TestWireBrainRegistry_InstallsVoIPlanner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := brain.NewRegistry(ctx, append(
		[]brain.System{brain.BeliefSystem},
		brain.ExecutorSystems()...,
	)...)
	beliefSchemaRegistry, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	wireBrainRegistry(ctx, registry, testTenantBeliefs(t, beliefSchemaRegistry, nil), beliefSchemaRegistry)

	e := registry.For("tenant-voi-wire-test") // triggers the OnEngine hook
	e.Submit(brain.MissionProjected{ID: "m1", Goal: "find a path"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		plans := e.VoIPlanSnapshot()
		if len(plans) == 1 && plans[0].MissionID == "m1" && !plans[0].InFlight {
			return // VoIGateSystem requested a plan, VoIWorker completed it
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("mission m1 never got a completed VoI plan within the deadline")
}

// TestWireBrainRegistry_InstallsReputationLoop proves wireBrainRegistry also
// installs the reputation write loop (gibson#267) live: a settled bet updates
// its technique×environment reputation, readable back through the belief
// substrate within a few ticks — the same way the VoI test above proves VoI
// planning is wired. Before this, Engine.UpdateReputation was reachable only by
// false liveness (an exported method on a reachable type, no real caller).
func TestWireBrainRegistry_InstallsReputationLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := brain.NewRegistry(ctx, append(
		[]brain.System{brain.BeliefSystem},
		brain.ExecutorSystems()...,
	)...)
	beliefSchemaRegistry, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	wireBrainRegistry(ctx, registry, testTenantBeliefs(t, beliefSchemaRegistry, nil), beliefSchemaRegistry)

	e := registry.For("tenant-reputation-wire-test") // triggers the OnEngine hook
	e.Submit(brain.HypothesisObserved{HypothesisID: "hyp-1", ScopeID: "scope-a", Claim: "c", Technique: "t1190"})

	// The engine's own tick loop folds the hypothesis asynchronously; the HITL
	// settle path resolves the technique×environment key FROM that folded
	// hypothesis, so wait for it before settling.
	foldDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(foldDeadline) {
		if len(e.Hypotheses()) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := e.SettleBetByHITL(ctx, brain.BetHITLRequest{
		HypothesisID: "hyp-1", Verdict: brain.VerdictTruePositive, UserID: "reviewer-1",
	}); err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}

	substrate := brain.NewWorldBeliefSubstrate(e)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok, _ := brain.ReadReputation(ctx, e.World.Tenant, "t1190", "scope-a", substrate); ok {
			return // the reputation write loop ran end to end
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("a settled bet never updated its reputation within the deadline")
}
