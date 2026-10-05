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
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// voiEngine wires a minimal goal-mission engine with the VoI gate installed,
// mirroring belief_test.go's beliefEngine / decider_test.go's goalEngine
// helpers. The worker is returned for off-tick draining. No capability
// catalog or hierarchy: tests exercising the technique -> capability bridge
// use voiEngineWithCatalog instead.
func voiEngine(substrate BeliefSubstrate, registry *ontology.BeliefSchemaRegistry, scorer VoIScorer, topK int) (*Engine, *VoIWorker) {
	return voiEngineWithCatalog(substrate, registry, scorer, topK, nil, nil)
}

// voiEngineWithCatalog is voiEngine plus an explicit capability catalog and
// technique hierarchy, for tests proving VoI dispatch gating's
// CoveringCapabilities resolution (ADR-0135, gibson#387).
func voiEngineWithCatalog(
	substrate BeliefSubstrate,
	registry *ontology.BeliefSchemaRegistry,
	scorer VoIScorer,
	topK int,
	catalog func(missionID string) []Capability,
	hierarchy *taxonomy.TechniqueHierarchy,
) (*Engine, *VoIWorker) {
	e := NewEngine("t")
	e.AddSystem(VoIGateSystem)
	w := NewVoIWorker(e, substrate, registry, scorer, topK, catalog, hierarchy, testBAMCPPlanner(registry))
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

// TestEngine_VoIPlanSnapshot proves the Engine-level accessor (the
// RLock-guarded read path daemon.go's tests/a future admin surface use,
// mirroring Hosts()/Hypotheses()) returns the same content World's own
// VoIPlanSnapshot does, without reaching into World directly.
func TestEngine_VoIPlanSnapshot(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	voiSettle(e, w, 1)

	got := e.VoIPlanSnapshot()
	if len(got) != 1 || got[0].MissionID != "m1" {
		t.Fatalf("VoIPlanSnapshot() = %+v, want one plan for m1", got)
	}
	if want := e.World.VoIPlanSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Engine.VoIPlanSnapshot() = %+v, want World.VoIPlanSnapshot() = %+v", got, want)
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
	WireVoIPlanner(ctx, e, registry, ExactVoIScorer(), DefaultVoITopK, 5*time.Millisecond, nil, nil, testBAMCPPlanner(registry))

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

// TestNewVoIWorker_NilCatalogAndHierarchyNeverPanic proves NewVoIWorker's nil
// catalog/hierarchy defaults (mirroring NewDeciderWorker's own nil-catalog
// convention) make a fully-usable worker: draining a plan for a hypothesis
// with a technique set resolves no covering capabilities, never a panic.
func TestNewVoIWorker_NilCatalogAndHierarchyNeverPanic(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngineWithCatalog(substrate, registry, ExactVoIScorer(), DefaultVoITopK, nil, nil)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HypothesisObserved{ScopeID: "s", Claim: "c", Proposer: "agent-1", Technique: "indirect_prompt_injection"})

	voiSettle(e, w, 1)

	plans := e.World.VoIPlanSnapshot()
	if len(plans) != 1 || len(plans[0].Candidates) != 1 {
		t.Fatalf("plans = %+v, want one plan with one candidate", plans)
	}
	if got := plans[0].Candidates[0].CoveringCapabilities; len(got) != 0 {
		t.Fatalf("CoveringCapabilities = %+v, want none (no catalog supplied)", got)
	}
}

// TestVoIWorker_ResolvesCoveringCapabilitiesFromItsLiveCatalog proves the
// worker's own catalog/hierarchy (NewVoIWorker's trailing params, ADR-0135/gibson#387)
// reach PlanVoI end-to-end through a live tick/drain
// cycle, not just through a directly-constructed VoIPlanInput: a hypothesis
// candidate's technique resolves against the mission id the gate/worker
// actually dispatched with.
func TestVoIWorker_ResolvesCoveringCapabilitiesFromItsLiveCatalog(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	hierarchy := dispatchTestHierarchy(t)
	generalist := Capability{Kind: "agent", Name: "injection-hunter",
		Coverage: dispatchCoverage(t, hierarchy, []taxonomy.CategoryID{"prompt_injection"}, nil)}

	var gotMissionID string
	catalog := func(missionID string) []Capability {
		gotMissionID = missionID
		return []Capability{generalist}
	}

	e, w := voiEngineWithCatalog(substrate, registry, ExactVoIScorer(), DefaultVoITopK, catalog, hierarchy)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HypothesisObserved{ScopeID: "s", Claim: "the filter is bypassable", Proposer: "agent-1", Technique: "indirect_prompt_injection"})

	voiSettle(e, w, 1)

	if gotMissionID != "m1" {
		t.Fatalf("catalog called with mission id %q, want %q", gotMissionID, "m1")
	}
	plans := e.World.VoIPlanSnapshot()
	if len(plans) != 1 || len(plans[0].Candidates) != 1 {
		t.Fatalf("plans = %+v, want one plan with one candidate", plans)
	}
	c := plans[0].Candidates[0]
	if len(c.CoveringCapabilities) != 1 || c.CoveringCapabilities[0].Name != "injection-hunter" {
		t.Fatalf("CoveringCapabilities = %+v, want only %q", c.CoveringCapabilities, "injection-hunter")
	}
}

// TestVoIWorker_BoundsToTopK proves the recorded plan is bounded, not the
// full candidate set — "VoI gates to top-k" (ADR-0126).
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
// simulator call) never blocks the ~50ms tick budget (ADR-0126).
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

// -----------------------------------------------------------------------
// gibson#341: VoIPlanRequested/VoIPlanned were never registered in
// timeline_codec.go (registerEvent + dereferenceEvent), and VoIPlanState was
// missing from world_snapshot.go's round trip. In-memory replay
// (TestVoIWorker_ReplayReproducesThePlan above, via Replay()->Reduce
// directly) was never affected — the gap is specifically the DURABLE store
// path (EncodeEvent/DecodeEvent, used by a TimelineStore) and the
// snapshot-and-trim path (ADR-0163's SnapshotWorld/RestoreWorld), both of
// which a live daemon actually uses and neither of which Replay exercises.
// -----------------------------------------------------------------------

// TestTimelineCodec_EncodeDecode_VoIPlanRequested proves a VoIPlanRequested
// event survives the JSON envelope round trip DecodeEvent(EncodeEvent(ev))
// uses for durable persistence — this failed with "unknown event kind
// \"voi.plan.requested\"" before the registerEvent/dereferenceEvent entries
// existed.
func TestTimelineCodec_EncodeDecode_VoIPlanRequested(t *testing.T) {
	want := VoIPlanRequested{MissionID: "m1", Cursor: 3}
	data, err := EncodeEvent(want)
	if err != nil {
		t.Fatalf("EncodeEvent: %v", err)
	}
	got, err := DecodeEvent(data)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if !reflect.DeepEqual(got, Event(want)) {
		t.Fatalf("round trip:\n got  %+v\nwant %+v", got, want)
	}
}

// TestTimelineCodec_EncodeDecode_VoIPlanned proves a VoIPlanned event
// survives the same round trip, including its nested Candidates slice —
// proving the payload, not just the envelope's kind string, decodes
// correctly. The first candidate's Technique/CoveringCapabilities (ADR-0135,
// gibson#387) exercise the exact reason CoveringCapabilities is
// []CapabilityRef and not []Capability: a Capability's Coverage carries
// unexported internal state the JSON codec would silently drop, so a ref
// (plain exported strings) is what must survive this round trip intact.
func TestTimelineCodec_EncodeDecode_VoIPlanned(t *testing.T) {
	want := VoIPlanned{
		MissionID: "m1",
		Cursor:    3,
		Candidates: []VoICandidate{
			{
				Kind: VoICandidateHypothesis, RefID: "hyp-1", InfoGain: 0.5, Value: 0.9,
				Technique:            "indirect_prompt_injection",
				CoveringCapabilities: []CapabilityRef{{Kind: "agent", Name: "injection-hunter"}},
			},
			{Kind: VoICandidateEvidence, RefID: "host-1", InfoGain: 0.2, Value: 0.3},
		},
	}
	data, err := EncodeEvent(want)
	if err != nil {
		t.Fatalf("EncodeEvent: %v", err)
	}
	got, err := DecodeEvent(data)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if !reflect.DeepEqual(got, Event(want)) {
		t.Fatalf("round trip:\n got  %+v\nwant %+v", got, want)
	}
}

// TestSnapshotRestore_RoundTripsVoIPlanState_InFlight proves an in-flight
// VoI plan (requested, not yet completed) survives a snapshot-and-restore
// cycle (ADR-0163) — the exact scenario a snapshot-and-trim right after a
// VoIGateSystem request, before VoIWorker completes it, would hit. Before
// this fix, VoIPlanState had no entry in worldSnapshotData at all, so
// RestoreWorld silently produced a World with no memory of it ever having
// been requested.
func TestSnapshotRestore_RoundTripsVoIPlanState_InFlight(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, VoIPlanRequested{MissionID: "m1", Cursor: 2})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.VoIPlanSnapshot(), w.VoIPlanSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("VoI plan state did not round-trip:\n got  %+v\nwant %+v", got, want)
	}
	if len(restored.VoIPlanSnapshot()) != 1 || !restored.VoIPlanSnapshot()[0].InFlight {
		t.Fatalf("want the restored plan still in flight, got %+v", restored.VoIPlanSnapshot())
	}
}

// TestSnapshotRestore_RoundTripsVoIPlanState_Completed proves a completed VoI
// plan (with its ranked candidates) survives the same round trip, including a
// candidate's Technique/CoveringCapabilities (ADR-0135,
// gibson#387) — the same JSON-safety property
// TestTimelineCodec_EncodeDecode_VoIPlanned proves for the durable Timeline
// path, proven here for the snapshot-and-trim path (ADR-0163), which
// round-trips through the same encoding/json marshal (world_snapshot.go).
func TestSnapshotRestore_RoundTripsVoIPlanState_Completed(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, VoIPlanRequested{MissionID: "m1", Cursor: 2})
	Reduce(w, VoIPlanned{
		MissionID: "m1",
		Cursor:    2,
		Candidates: []VoICandidate{
			{
				Kind: VoICandidateHypothesis, RefID: "hyp-1", Value: 0.9,
				Technique:            "indirect_prompt_injection",
				CoveringCapabilities: []CapabilityRef{{Kind: "agent", Name: "injection-hunter"}},
			},
		},
	})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.VoIPlanSnapshot(), w.VoIPlanSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("VoI plan state did not round-trip:\n got  %+v\nwant %+v", got, want)
	}
	if restored.VoIPlanSnapshot()[0].InFlight {
		t.Fatal("want the restored plan NOT in flight (it completed)")
	}
}
