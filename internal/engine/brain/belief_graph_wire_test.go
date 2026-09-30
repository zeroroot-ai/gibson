// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// liveBeliefRegistry builds the real, shipped core belief schema (gibson#296)
// — the same registry the daemon constructs in production — so these tests
// exercise the actual integration boundary, not a hand-rolled test schema.
func liveBeliefRegistry(t *testing.T) *ontology.BeliefSchemaRegistry {
	t.Helper()
	reg := ontology.NewBeliefSchemaRegistry()
	if err := ontology.RegisterCoreBeliefSchemaSeed(reg); err != nil {
		t.Fatalf("RegisterCoreBeliefSchemaSeed: %v", err)
	}
	return reg
}

// TestSliceBeliefRound_ScoresEveryHostAndAppliesOnTick proves one full
// graph-coupled round — derive the live graph from the engine's hosts, Check
// each, Drain — ends with every host's Belief updated once the engine ticks
// the resulting BeliefScored events (WorldBeliefSubstrate's write path).
func TestSliceBeliefRound_ScoresEveryHostAndAppliesOnTick(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{80}})
	settle(e, bw, 1) // per-host evidence pipeline settles first, as it would live

	registry := liveBeliefRegistry(t)
	substrate := NewWorldBeliefSubstrate(e)
	gate := NewSliceGate(substrate)
	provider := &fakeSliceBeliefProvider{}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()

	checked, scored, err := SliceBeliefRound(ctx, e, registry, gate, worker, SliceOptions{MaxDepth: 3, NodeBudget: 50}, SliceOptions{MaxDepth: 2, NodeBudget: 50})
	if err != nil {
		t.Fatalf("SliceBeliefRound: %v", err)
	}
	if checked != 2 {
		t.Fatalf("checked = %d, want 2 (both hosts)", checked)
	}
	if scored != 2 {
		t.Fatalf("scored = %d, want 2 (both requested on the first round)", scored)
	}

	// Not applied yet: SetBelief only Submits, folded on the next Tick.
	e.Tick()

	for _, h := range e.World.Snapshot() {
		if h.Belief.Model != "fake-v0" {
			t.Errorf("host %s Belief.Model = %q, want fake-v0 (the graph-coupled provider's score)", h.Address, h.Belief.Model)
		}
	}
}

// TestSliceBeliefRound_QuiescentOnSecondRound proves the graph-coupled round
// is gated exactly like the per-host one: nothing changed between rounds, so
// the second round checks every host again (cheap) but scores none.
func TestSliceBeliefRound_QuiescentOnSecondRound(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)

	registry := liveBeliefRegistry(t)
	substrate := NewWorldBeliefSubstrate(e)
	gate := NewSliceGate(substrate)
	provider := &fakeSliceBeliefProvider{}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()
	opts := SliceOptions{MaxDepth: 3, NodeBudget: 50}

	if _, _, err := SliceBeliefRound(ctx, e, registry, gate, worker, opts, opts); err != nil {
		t.Fatalf("first round: %v", err)
	}
	e.Tick()

	_, scored, err := SliceBeliefRound(ctx, e, registry, gate, worker, opts, opts)
	if err != nil {
		t.Fatalf("second round: %v", err)
	}
	if scored != 0 {
		t.Fatalf("second round scored %d, want 0 (nothing changed)", scored)
	}
}

// TestSliceBeliefRound_EvidenceChangeReScoresThatHost proves the graph-coupled
// gate reacts to the SAME evidence changes the per-host gate does — a host's
// belief changing (from new evidence, via the ordinary per-host pipeline)
// moves that host's slice-digest, so the next round re-requests it.
func TestSliceBeliefRound_EvidenceChangeReScoresThatHost(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)

	registry := liveBeliefRegistry(t)
	substrate := NewWorldBeliefSubstrate(e)
	gate := NewSliceGate(substrate)
	provider := &fakeSliceBeliefProvider{}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()
	opts := SliceOptions{MaxDepth: 3, NodeBudget: 50}

	if _, _, err := SliceBeliefRound(ctx, e, registry, gate, worker, opts, opts); err != nil {
		t.Fatalf("first round: %v", err)
	}
	e.Tick()

	// New evidence: another open port changes the host's own belief via the
	// EXISTING per-host pipeline (unchanged).
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 443}})
	settle(e, bw, 1)

	_, scored, err := SliceBeliefRound(ctx, e, registry, gate, worker, opts, opts)
	if err != nil {
		t.Fatalf("second round: %v", err)
	}
	if scored != 1 {
		t.Fatalf("second round scored %d, want 1 (the host whose evidence changed)", scored)
	}
}

// TestWireSliceBelief_RunsOffTheEngineTick proves the graph-coupled pipeline
// is wired the same way WireBelief is: a slow provider blocks only the
// off-tick round, never the engine's own Tick — the acceptance criterion
// "the ~50ms tick never blocks" is a structural property of running this
// entirely outside runSystems, and this pins it end to end through
// WireSliceBelief itself, not just its pieces.
func TestWireSliceBelief_RunsOffTheEngineTick(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)

	registry := liveBeliefRegistry(t)
	release := make(chan struct{})
	provider := &fakeSliceBeliefProvider{release: release}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate := WireSliceBelief(ctx, e, registry, provider, 5*time.Millisecond,
		SliceOptions{MaxDepth: 3, NodeBudget: 50}, SliceOptions{MaxDepth: 2, NodeBudget: 50})
	if gate == nil {
		t.Fatalf("WireSliceBelief returned a nil gate")
	}
	waitFor(t, func() bool { return provider.count() >= 1 })

	start := time.Now()
	for range 20 {
		e.Tick()
	}
	if elapsed := time.Since(start); elapsed >= 200*time.Millisecond {
		t.Fatalf("20 engine ticks took %v while the graph-coupled provider was blocked — it stalled the tick", elapsed)
	}

	close(release)
}

// TestDefaultSliceSchedule_MatchesTheDocumentedConstants pins the bound
// gibson#275's acceptance criterion ("propagation is bounded... documented
// bound") actually names — a test that would fail the moment the constants
// and the schedule builder drift apart.
func TestDefaultSliceSchedule_MatchesTheDocumentedConstants(t *testing.T) {
	sliceOpts, propagateOpts := DefaultSliceSchedule()
	want := SliceOptions{MaxDepth: DefaultSliceMaxDepth, NodeBudget: DefaultSliceNodeBudget}
	if sliceOpts != want {
		t.Fatalf("sliceOpts = %+v, want %+v", sliceOpts, want)
	}
	wantPropagate := SliceOptions{MaxDepth: DefaultPropagateMaxDepth, NodeBudget: DefaultPropagateNodeBudget}
	if propagateOpts != wantPropagate {
		t.Fatalf("propagateOpts = %+v, want %+v", propagateOpts, wantPropagate)
	}
}

// TestSliceBeliefRound_PropagatesCheckError proves a round surfaces a Check
// failure (a bad substrate read) rather than silently treating it as nothing
// to score.
func TestSliceBeliefRound_PropagatesCheckError(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)
	hostID := e.World.Snapshot()[0].ID

	registry := liveBeliefRegistry(t)
	substrate := &erroringBeliefSubstrate{
		fakeBeliefSubstrate: newFakeBeliefSubstrate(),
		failBeliefFor:       NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)},
	}
	gate := NewSliceGate(substrate)
	worker := NewSliceBeliefWorker(gate, &fakeSliceBeliefProvider{})
	opts := SliceOptions{MaxDepth: 3, NodeBudget: 50}

	if _, _, err := SliceBeliefRound(context.Background(), e, registry, gate, worker, opts, opts); err == nil {
		t.Fatalf("SliceBeliefRound did not propagate the Check error")
	}
}

// TestSliceBeliefRound_PropagatesDrainError proves a round surfaces a Drain
// failure (here, Apply rejecting a write) rather than reporting success.
func TestSliceBeliefRound_PropagatesDrainError(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)
	hostID := e.World.Snapshot()[0].ID
	hostRef := NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)}

	registry := liveBeliefRegistry(t)
	substrate := &erroringBeliefSubstrate{fakeBeliefSubstrate: newFakeBeliefSubstrate(), failSetBeliefFor: hostRef}
	gate := NewSliceGate(substrate)
	worker := NewSliceBeliefWorker(gate, &fakeSliceBeliefProvider{})
	opts := SliceOptions{MaxDepth: 3, NodeBudget: 50}

	if _, _, err := SliceBeliefRound(context.Background(), e, registry, gate, worker, opts, opts); err == nil {
		t.Fatalf("SliceBeliefRound did not propagate the Drain/Apply error")
	}
}

// TestWireSliceBelief_DefaultsNonPositiveInterval proves interval <= 0 falls
// back to TickInterval (the same convention WireBelief uses) rather than a
// busy loop or no ticking at all.
func TestWireSliceBelief_DefaultsNonPositiveInterval(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)

	registry := liveBeliefRegistry(t)
	provider := &fakeSliceBeliefProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sliceOpts, propagateOpts := DefaultSliceSchedule()
	gate := WireSliceBelief(ctx, e, registry, provider, 0, sliceOpts, propagateOpts)
	if gate == nil {
		t.Fatalf("WireSliceBelief returned a nil gate")
	}
	waitFor(t, func() bool { return provider.count() >= 1 })
}
