// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// TestResolveBeliefProvider_DefaultsToTheEmbeddedBaseModel proves that
// without a GIBSON_BELIEF_MODEL_PATH override the daemon scores in-process
// against the OSS-embedded base-v1 model (ADR-0134) — no sidecar, no
// placeholder fallback, since the native engine has no deployment cost left
// to opt out of.
func TestResolveBeliefProvider_DefaultsToTheEmbeddedBaseModel(t *testing.T) {
	t.Setenv("GIBSON_BELIEF_MODEL_PATH", "")
	p, err := resolveBeliefProvider()
	if err != nil {
		t.Fatalf("resolveBeliefProvider: %v", err)
	}
	if got := p.Version(); got != "base-v1" {
		t.Fatalf("default provider version = %q, want base-v1", got)
	}
}

// TestResolveBeliefProvider_PinsAnOverrideModelPath proves GIBSON_BELIEF_MODEL_PATH
// selects an alternate model artifact (e.g. a curated commercial base model
// dropped in by the commercial layer), ADR-0129.
func TestResolveBeliefProvider_PinsAnOverrideModelPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base-v3.json")
	const raw = `{
  "version": "base-v3",
  "variables": ["reachable", "exploitable", "juicy"],
  "edges": [["reachable", "exploitable"], ["exploitable", "juicy"]],
  "cpds": {
    "reachable": {"values": [[0.5], [0.5]]},
    "exploitable": {"evidence": ["reachable"], "evidence_card": [2], "values": [[0.9, 0.2], [0.1, 0.8]]},
    "juicy": {"evidence": ["exploitable"], "evidence_card": [2], "values": [[0.9, 0.3], [0.1, 0.7]]}
  }
}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GIBSON_BELIEF_MODEL_PATH", path)
	p, err := resolveBeliefProvider()
	if err != nil {
		t.Fatalf("resolveBeliefProvider: %v", err)
	}
	if got := p.Version(); got != "base-v3" {
		t.Fatalf("pinned provider version = %q, want base-v3", got)
	}
}

// TestResolveBeliefProvider_FailsLoudOnAnInvalidOverride proves a
// misconfigured GIBSON_BELIEF_MODEL_PATH fails daemon startup rather than
// silently falling back to a different model (fail-loud on a real
// dependency, matching every other resolve* helper in this file).
func TestResolveBeliefProvider_FailsLoudOnAnInvalidOverride(t *testing.T) {
	t.Setenv("GIBSON_BELIEF_MODEL_PATH", filepath.Join(t.TempDir(), "does-not-exist.json"))
	if _, err := resolveBeliefProvider(); err == nil {
		t.Fatal("expected an error for a missing model artifact file")
	}
}

// TestResolveSliceBeliefProvider_IsTheNativeGroundingProvider pins today's
// documented state (belief_provider.go, gibson#394/ADR-0137): the
// graph-coupled SliceBeliefProvider grounds the registry's declared belief-PRM
// schema in-process via beliefvi (brain.NativeSliceBeliefProvider), never the
// deterministic placeholder — the ontology's per-edge-type target-variable
// declaration (ADR-0137) is what unblocked the switch.
func TestResolveSliceBeliefProvider_IsTheNativeGroundingProvider(t *testing.T) {
	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	p := resolveSliceBeliefProvider(reg, nil)
	if got := p.Version(); got != "native-slice-v0-uninformative-prior" {
		t.Fatalf("resolveSliceBeliefProvider version = %q, want native-slice-v0-uninformative-prior", got)
	}
}

// TestResolveEdgePosteriorProvider_DefaultsToNilWhenUnset proves the
// gibson#395 documented data caveat: with no GIBSON_EDGE_POSTERIOR_PATH the
// daemon pins no posterior at all, which NativeSliceBeliefProvider and
// NewBAMCPPlanner both already treat as the uninformative-prior cold start —
// production is allowed to have no recorded outcomes yet.
func TestResolveEdgePosteriorProvider_DefaultsToNilWhenUnset(t *testing.T) {
	t.Setenv("GIBSON_EDGE_POSTERIOR_PATH", "")
	p, err := resolveEdgePosteriorProvider()
	if err != nil {
		t.Fatalf("resolveEdgePosteriorProvider: %v", err)
	}
	if p != nil {
		t.Fatalf("expected a nil provider when GIBSON_EDGE_POSTERIOR_PATH is unset, got %v", p)
	}
}

// TestResolveEdgePosteriorProvider_PinsAFittedArtifact proves
// GIBSON_EDGE_POSTERIOR_PATH selects a braintrain-fitted edge-posterior
// artifact (gibson#395, ADR-0137).
func TestResolveEdgePosteriorProvider_PinsAFittedArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tenant-acme-edges-v3.json")
	const raw = `{"version":"tenant-acme-edges-v3","posteriors":{"RESOLVES_TO":{"alpha":8,"beta":4}}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GIBSON_EDGE_POSTERIOR_PATH", path)
	p, err := resolveEdgePosteriorProvider()
	if err != nil {
		t.Fatalf("resolveEdgePosteriorProvider: %v", err)
	}
	if got := p.Version(); got != "tenant-acme-edges-v3" {
		t.Fatalf("pinned provider version = %q, want tenant-acme-edges-v3", got)
	}
	if got := p.Posterior("RESOLVES_TO").Mean(); got != 8.0/12.0 {
		t.Fatalf("RESOLVES_TO mean = %v, want %v", got, 8.0/12.0)
	}
}

// TestResolveEdgePosteriorProvider_FailsLoudOnAnInvalidOverride mirrors
// TestResolveBeliefProvider_FailsLoudOnAnInvalidOverride: a misconfigured
// GIBSON_EDGE_POSTERIOR_PATH fails daemon startup rather than silently
// falling back to the cold start.
func TestResolveEdgePosteriorProvider_FailsLoudOnAnInvalidOverride(t *testing.T) {
	t.Setenv("GIBSON_EDGE_POSTERIOR_PATH", filepath.Join(t.TempDir(), "does-not-exist.json"))
	if _, err := resolveEdgePosteriorProvider(); err == nil {
		t.Fatal("expected an error for a missing edge posterior artifact file")
	}
}

// TestResolveSliceBeliefProvider_PinsThePosteriorVersionIntoItsOwnVersion
// proves resolveSliceBeliefProvider actually threads a resolved posterior
// provider into brain.NativeSliceBeliefProvider rather than dropping it
// (gibson#395's mission-pin requirement starts here: Version() is what a
// scored node's Belief.Model gets stamped with).
func TestResolveSliceBeliefProvider_PinsThePosteriorVersionIntoItsOwnVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tenant-acme-edges-v1.json")
	const raw = `{"version":"tenant-acme-edges-v1","posteriors":{}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIBSON_EDGE_POSTERIOR_PATH", path)
	posteriors, err := resolveEdgePosteriorProvider()
	if err != nil {
		t.Fatalf("resolveEdgePosteriorProvider: %v", err)
	}

	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	p := resolveSliceBeliefProvider(reg, posteriors)
	want := "native-slice-v0-uninformative-prior+edges:tenant-acme-edges-v1"
	if got := p.Version(); got != want {
		t.Fatalf("resolveSliceBeliefProvider version = %q, want %q", got, want)
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
	beliefProvider, err := resolveBeliefProvider()
	if err != nil {
		t.Fatalf("resolveBeliefProvider: %v", err)
	}
	wireBrainRegistry(ctx, registry, beliefProvider, resolveSliceBeliefProvider(beliefSchemaRegistry, nil), beliefSchemaRegistry, nil)

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
	beliefProvider, err := resolveBeliefProvider()
	if err != nil {
		t.Fatalf("resolveBeliefProvider: %v", err)
	}
	wireBrainRegistry(ctx, registry, beliefProvider, resolveSliceBeliefProvider(beliefSchemaRegistry, nil), beliefSchemaRegistry, nil)

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
	beliefProvider, err := resolveBeliefProvider()
	if err != nil {
		t.Fatalf("resolveBeliefProvider: %v", err)
	}
	wireBrainRegistry(ctx, registry, beliefProvider, resolveSliceBeliefProvider(beliefSchemaRegistry, nil), beliefSchemaRegistry, nil)

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
