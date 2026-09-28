// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// voiEngine wires a minimal goal-mission engine with the VoI gate installed,
// mirroring belief_test.go's beliefEngine / decider_test.go's goalEngine
// helpers. The worker is returned for off-tick draining.
func voiEngine(substrate BeliefSubstrate, registry *ontology.BeliefSchemaRegistry, scorer VoIScorer, topK int) (*Engine, *VoIWorker) {
	e := NewEngine("t")
	e.AddSystem(VoIGateSystem)
	w := NewVoIWorker(e, substrate, registry, scorer, topK)
	e.Subscribe(w.Tap)
	return e, w
}

// voiSettle mirrors belief_test.go's settle(): tick (gate fires) -> drain
// (off-tick scoring) -> tick (fold the result).
func voiSettle(e *Engine, w *VoIWorker, rounds int) {
	for range rounds {
		e.Tick()
		w.Drain(context.Background())
		e.Tick()
	}
}

// TestVoIGateSystem_RequestsOncePerEvidenceChange mirrors
// TestBeliefSystem_ConsultsProviderOnEvidenceChange: a running goal mission
// with no VoI plan yet always gets one; a repeated sweep with nothing new is
// quiescent.
func TestVoIGateSystem_RequestsOncePerEvidenceChange(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})

	voiSettle(e, w, 1)
	plans := e.World.VoIPlanSnapshot()
	if len(plans) != 1 || plans[0].MissionID != "m1" {
		t.Fatalf("plans = %+v, want one plan for m1", plans)
	}

	// Quiescent: nothing changed, so draining again does no work.
	if n := w.Drain(context.Background()); n != 0 {
		t.Fatalf("second Drain scored %d missions, want 0 (nothing changed)", n)
	}
}

// TestVoIPlanEvents_Kind proves the event Kind() strings, the same convention
// every other Timeline event in this package follows.
func TestVoIPlanEvents_Kind(t *testing.T) {
	if got := (VoIPlanRequested{}).Kind(); got != "voi.plan.requested" {
		t.Fatalf("VoIPlanRequested.Kind() = %q", got)
	}
	if got := (VoIPlanned{}).Kind(); got != "voi.plan.completed" {
		t.Fatalf("VoIPlanned.Kind() = %q", got)
	}
}

// TestVoIGateSystem_SkipsMissionsNotEligible proves the gate ignores a mission
// that is not running (paused) and a no-goal (scripted) mission, mirroring
// DeciderGateSystem's own eligibility check — only running goal missions get a
// VoI plan.
func TestVoIGateSystem_SkipsMissionsNotEligible(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "no-goal"}) // Goal == "" : scripted mission
	e.Submit(MissionProjected{ID: "paused", Goal: "find a path"})
	e.Submit(MissionPauseRequested{ID: "paused"})

	voiSettle(e, w, 1)

	if plans := e.World.VoIPlanSnapshot(); len(plans) != 0 {
		t.Fatalf("plans = %+v, want none (no eligible goal mission)", plans)
	}
}

// TestApplyVoIPlanned_DefensivelyRecordsAnUnrequestedPlan proves the reducer
// never drops a completed plan even if no VoIPlanRequested preceded it
// (should not happen live — the worker only plans a mission it Tapped a
// request for — but the reducer must still be total over its own event type).
func TestApplyVoIPlanned_DefensivelyRecordsAnUnrequestedPlan(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, VoIPlanned{MissionID: "m1", Candidates: []VoICandidate{{RefID: "h1"}}})

	plans := w.VoIPlanSnapshot()
	if len(plans) != 1 || plans[0].MissionID != "m1" || plans[0].InFlight {
		t.Fatalf("plans = %+v, want one completed (not in-flight) plan for m1", plans)
	}
}

// TestVoIWorker_FailedPlanClearsInFlightWithNoCandidates proves a substrate
// error during planning does not wedge the mission permanently in-flight —
// the same non-fatal failure handling DeciderWorker.decide uses for a failed
// LLM call: clear in-flight, record no candidates, let the gate retry.
func TestVoIWorker_FailedPlanClearsInFlightWithNoCandidates(t *testing.T) {
	substrate := &erroringBeliefSubstrate{
		fakeBeliefSubstrate: newFakeBeliefSubstrate(),
		failBeliefFor:       NodeRef{Kind: NodeKindClaim, ID: "t/1"}, // "t": the engine's tenant; "1": the first assigned hypothesis id
	}
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HypothesisObserved{ScopeID: "s", Claim: "port 22 is exploitable", Proposer: "agent-1"})

	voiSettle(e, w, 1)

	plans := e.World.VoIPlanSnapshot()
	if len(plans) != 1 || plans[0].InFlight || plans[0].Candidates != nil {
		t.Fatalf("plans = %+v, want one completed plan with no candidates (planning failed)", plans)
	}
}

// TestWireVoIPlanner_ProducesAReplayablePlanOffTheTick is the end-to-end wiring
// test: WireVoIPlanner's own ticker (not a test-driven Drain) settles a plan,
// proving the exported entry point the daemon will call actually works, and
// that cancelling ctx stops the goroutine cleanly (the ctx.Done() drain path).
func TestWireVoIPlanner_ProducesAReplayablePlanOffTheTick(t *testing.T) {
	registry := liveBeliefRegistry(t)
	e := NewEngine("t")
	e.AddSystem(VoIGateSystem)
	ctx, cancel := context.WithCancel(context.Background())
	WireVoIPlanner(ctx, e, registry, ExactVoIScorer(), DefaultVoITopK, 5*time.Millisecond)

	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Tick()

	waitFor(t, func() bool {
		e.Tick()
		plans := e.World.VoIPlanSnapshot()
		return len(plans) == 1 && !plans[0].InFlight && len(plans[0].Candidates) == 1
	})

	cancel()
}

// TestVoIWorker_RecordsRankedCandidates proves the worker actually calls
// PlanVoI against the mission's hosts/hypotheses and records the ranked,
// bounded result as a replayable VoIPlanSnapshot.
func TestVoIWorker_RecordsRankedCandidates(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Submit(HypothesisObserved{ScopeID: "s", Claim: "port 22 is exploitable", Proposer: "agent-1"})

	voiSettle(e, w, 1)

	plans := e.World.VoIPlanSnapshot()
	if len(plans) != 1 {
		t.Fatalf("got %d plans, want 1", len(plans))
	}
	plan := plans[0]
	if len(plan.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 (one host, one hypothesis): %+v", len(plan.Candidates), plan.Candidates)
	}
	kinds := map[VoICandidateKind]bool{}
	for _, c := range plan.Candidates {
		kinds[c.Kind] = true
	}
	if !kinds[VoICandidateEvidence] || !kinds[VoICandidateHypothesis] {
		t.Fatalf("candidates = %+v, want both an evidence and a hypothesis candidate", plan.Candidates)
	}
}

// TestVoIWorker_BoundsToTopK proves the recorded plan is bounded, not the
// full candidate set — "VoI gates to top-k" (ADR-0026 §1).
func TestVoIWorker_BoundsToTopK(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), 1)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{80}})

	voiSettle(e, w, 1)

	plans := e.World.VoIPlanSnapshot()
	if len(plans) != 1 || len(plans[0].Candidates) != 1 {
		t.Fatalf("plans = %+v, want exactly 1 plan with 1 candidate (topK=1)", plans)
	}
}

// TestVoIWorker_ReplayReproducesThePlan proves the recorded plan folds
// identically on replay — the same World==fold(Timeline) discipline every
// other belief-engine event in this package holds to.
func TestVoIWorker_ReplayReproducesThePlan(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})

	voiSettle(e, w, 1)

	replayed := Replay("t", e.Timeline)
	if !reflect.DeepEqual(replayed.VoIPlanSnapshot(), e.World.VoIPlanSnapshot()) {
		t.Fatalf("replay diverged:\n got  %+v\nwant %+v", replayed.VoIPlanSnapshot(), e.World.VoIPlanSnapshot())
	}
}

// TestVoIWorker_SlowPlanningDoesNotStallTheTick proves VoI planning runs off
// the tick, exactly like the Decider and the belief workers — a slow
// substrate (standing in for what will eventually be an off-tick sidecar or
// simulator call) never blocks the ~50ms tick budget (ADR-0026 §4).
func TestVoIWorker_SlowPlanningDoesNotStallTheTick(t *testing.T) {
	release := make(chan struct{})
	substrate := &slowBeliefSubstrate{fakeBeliefSubstrate: newFakeBeliefSubstrate(), release: release}
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	// A hypothesis candidate guarantees a substrate.Belief call (the claim-node
	// read) — a host-only candidate set never touches the substrate today
	// (see resolveReputation's file doc comment in voi_plan.go).
	e.Submit(HypothesisObserved{ScopeID: "s", Claim: "port 22 is exploitable", Proposer: "agent-1"})
	e.Tick() // gate fires, worker taps

	done := make(chan struct{})
	go func() { defer close(done); w.Drain(context.Background()) }()
	waitFor(t, func() bool { return substrate.calls() >= 1 })

	start := time.Now()
	for range 20 {
		e.Tick()
	}
	if elapsed := time.Since(start); elapsed >= 200*time.Millisecond {
		t.Fatalf("20 engine ticks took %v while planning was blocked — it stalled the tick", elapsed)
	}

	close(release)
	<-done
}

// slowBeliefSubstrate wraps fakeBeliefSubstrate but blocks on Belief until
// release is closed, mirroring belief_test.go's countingBelief release
// pattern, to prove the VoI worker's substrate reads happen off-tick.
type slowBeliefSubstrate struct {
	*fakeBeliefSubstrate
	release chan struct{}

	mu sync.Mutex
	n  int
}

func (s *slowBeliefSubstrate) Belief(ctx context.Context, ref NodeRef) (NodeBelief, bool, error) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	<-s.release
	return s.fakeBeliefSubstrate.Belief(ctx, ref)
}

func (s *slowBeliefSubstrate) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}
