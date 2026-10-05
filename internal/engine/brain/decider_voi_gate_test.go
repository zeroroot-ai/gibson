// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// decider_voi_gate_test.go proves gibson#397's hard top-k gate itself
// (voiTopKCapabilities, DeciderWorker.voiGatedDispatch, and their wiring into
// DeciderWorker.decide): a candidate in the VoI top-k licenses its covering
// capability's dispatch, a capability no top-k candidate covers is refused
// even though it is a perfectly valid catalog member, and a mission with no
// VoI plan at all dispatches nothing — fail closed, never fail open
// (ADR-0027: no soft fallback). decider_test.go / decider_redispatch_test.go
// exercise catalog/JSON validation and seed a passing VoI top-k via
// approveViaVoI so those tests stay focused on what they were written to
// prove.

func TestVoiTopKCapabilities_EmptyCandidatesIsNil(t *testing.T) {
	if got := voiTopKCapabilities(nil); got != nil {
		t.Fatalf("no candidates: want nil, got %+v", got)
	}
	if got := voiTopKCapabilities([]VoICandidate{}); got != nil {
		t.Fatalf("empty candidate slice: want nil, got %+v", got)
	}
}

func TestVoiTopKCapabilities_CandidateWithNoCoverageContributesNothing(t *testing.T) {
	// An evidence-move candidate never carries a Technique (voi_plan.go), so
	// CoveringCapabilities is always nil — being ranked is not enough.
	candidates := []VoICandidate{
		{Kind: VoICandidateEvidence, RefID: "host-1"},
	}
	if got := voiTopKCapabilities(candidates); got != nil {
		t.Fatalf("uncovered candidate: want nil allow-set, got %+v", got)
	}
}

func TestVoiTopKCapabilities_UnionsAcrossCandidatesAndDedupes(t *testing.T) {
	candidates := []VoICandidate{
		{Kind: VoICandidateHypothesis, RefID: "h1", CoveringCapabilities: []CapabilityRef{
			{Kind: "agent", Name: "exploit"},
			{Kind: "tool", Name: "nmap"},
		}},
		{Kind: VoICandidateHypothesis, RefID: "h2", CoveringCapabilities: []CapabilityRef{
			{Kind: "tool", Name: "nmap"}, // duplicate of h1's — must not double-count or break
			{Kind: "plugin", Name: "gitleaks"},
		}},
		{Kind: VoICandidateEvidence, RefID: "host-1"}, // contributes nothing
	}
	got := voiTopKCapabilities(candidates)
	want := map[CapabilityRef]bool{
		{Kind: "agent", Name: "exploit"}:   true,
		{Kind: "tool", Name: "nmap"}:       true,
		{Kind: "plugin", Name: "gitleaks"}: true,
	}
	if len(got) != len(want) {
		t.Fatalf("allow-set size: got %+v, want %+v", got, want)
	}
	for ref := range want {
		if !got[ref] {
			t.Errorf("allow-set missing %+v: got %+v", ref, got)
		}
	}
	if got[CapabilityRef{Kind: "tool", Name: "metasploit"}] {
		t.Error("allow-set must not contain a capability no candidate covers")
	}
}

// voiGateEngine wires a goal-mission engine with the given catalog — like
// decider_test.go's goalEngine, but the catalog is a parameter so a test can
// offer a capability that is deliberately NOT covered by the seeded top-k.
func voiGateEngine(llm DeciderLLM, catalog func(string) []Capability) (*Engine, *DeciderWorker) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, llm, catalog)
	e.AddSystem(SchedulerSystem)
	e.AddSystem(DeciderGateSystem)
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)
	e.Subscribe(dw.Tap)
	return e, dw
}

func TestVoiGatedDispatch_NoPlanYetRefusesEverything(t *testing.T) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, nil, nil)
	// No VoIPlanned ever submitted for "m1" — VoIPlanSnapshot() is empty.
	if dw.voiGatedDispatch("m1", DeciderDispatch{Kind: "agent", Target: "exploit"}) {
		t.Fatal("a mission with no VoI plan at all must refuse every dispatch")
	}
}

func TestVoiGatedDispatch_CoveredCapabilityAllowed(t *testing.T) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, nil, nil)
	e.Submit(VoIPlanned{MissionID: "m1", Candidates: []VoICandidate{
		{Kind: VoICandidateHypothesis, RefID: "h1", CoveringCapabilities: []CapabilityRef{
			{Kind: "agent", Name: "exploit"},
		}},
	}})
	e.Tick()

	if !dw.voiGatedDispatch("m1", DeciderDispatch{Kind: "agent", Target: "exploit"}) {
		t.Fatal("a capability a top-k candidate covers must be allowed")
	}
}

func TestVoiGatedDispatch_UncoveredCapabilityRefused(t *testing.T) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, nil, nil)
	e.Submit(VoIPlanned{MissionID: "m1", Candidates: []VoICandidate{
		{Kind: VoICandidateHypothesis, RefID: "h1", CoveringCapabilities: []CapabilityRef{
			{Kind: "agent", Name: "exploit"},
		}},
	}})
	e.Tick()

	if dw.voiGatedDispatch("m1", DeciderDispatch{Kind: "tool", Target: "nmap"}) {
		t.Fatal("a capability no top-k candidate covers must be refused")
	}
}

func TestVoiGatedDispatch_ScopedToItsOwnMission(t *testing.T) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, nil, nil)
	e.Submit(VoIPlanned{MissionID: "m1", Candidates: []VoICandidate{
		{Kind: VoICandidateHypothesis, RefID: "h1", CoveringCapabilities: []CapabilityRef{
			{Kind: "agent", Name: "exploit"},
		}},
	}})
	e.Tick()

	// m2's plan does not exist — m1's approval must not leak across missions.
	if dw.voiGatedDispatch("m2", DeciderDispatch{Kind: "agent", Target: "exploit"}) {
		t.Fatal("VoI approval must not leak across missions")
	}
}

// TestDecider_OutOfTopKDispatchIsRefused is the fixture gibson#397's
// acceptance criteria asks for: the LLM proposes a dispatch to a catalog
// member the VoI top-k does not cover, and it must never reach the work
// queue, end to end through DeciderWorker.decide.
func TestDecider_OutOfTopKDispatchIsRefused(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		// "decoy" is a real catalog member (validateDispatch would pass it),
		// but no VoI candidate covers it.
		{Dispatches: []DeciderDispatch{{Kind: "agent", Target: "decoy", Input: "x"}}},
		{Complete: &DeciderComplete{Outcome: "success"}},
	}}
	e, dw := voiGateEngine(llm, func(string) []Capability {
		return []Capability{
			{Kind: "agent", Name: "exploit"},
			{Kind: "agent", Name: "decoy"},
		}
	})
	e.Submit(MissionProjected{ID: "m1", Goal: "find the flag"})
	approveViaVoI(e, "m1", Capability{Kind: "agent", Name: "exploit"}) // covers exploit, NOT decoy
	runRounds(e, dw, 8)

	if _, ok := dispatchedTargets(e)["decoy"]; ok {
		t.Fatalf("a capability outside the VoI top-k must never be dispatched; work=%+v", e.Work())
	}
}

// TestDecider_InTopKDispatchSucceeds is the positive twin of the above: the
// same shape, but the LLM targets the capability the top-k DOES cover.
func TestDecider_InTopKDispatchSucceeds(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "agent", Target: "exploit", Input: "x"}}},
		{Complete: &DeciderComplete{Outcome: "success"}},
	}}
	e, dw := voiGateEngine(llm, func(string) []Capability {
		return []Capability{
			{Kind: "agent", Name: "exploit"},
			{Kind: "agent", Name: "decoy"},
		}
	})
	e.Submit(MissionProjected{ID: "m1", Goal: "find the flag"})
	approveViaVoI(e, "m1", Capability{Kind: "agent", Name: "exploit"})
	runRounds(e, dw, 8)

	if got := dispatchedTargets(e)["exploit"]; got != WorkDone {
		t.Fatalf("exploit is covered by the VoI top-k and must dispatch; got %q, work=%+v", got, e.Work())
	}
}

// TestDecider_ColdMissionWithNoVoIPlanDispatchesNothing is the empty/edge
// case: a mission that has never had a VoI plan (BAMCP has not run a round
// for it yet, gibson#396) must not let anything through, even a dispatch a
// looser (catalog-only) check would have allowed.
func TestDecider_ColdMissionWithNoVoIPlanDispatchesNothing(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "agent", Target: "exploit", Input: "x"}}},
	}}
	e, dw := voiGateEngine(llm, func(string) []Capability {
		return []Capability{{Kind: "agent", Name: "exploit"}}
	})
	e.Submit(MissionProjected{ID: "m1", Goal: "find the flag"})
	// Deliberately no approveViaVoI call — no VoI plan exists for m1 at all.
	runRounds(e, dw, 4)

	if _, ok := dispatchedTargets(e)["exploit"]; ok {
		t.Fatalf("a mission with no VoI plan yet must dispatch nothing; work=%+v", e.Work())
	}
}

// A decision request waits while the VoI plan of the mission is in flight, and
// the Decider decides after the plan folds (gibson#693). Without the wait, the
// gate refuses the dispatch against the missing plan, and the quiescent mission
// ends with no work done.
func TestDeciderDrain_WaitsForTheVoIPlanInFlight(t *testing.T) {
	exploit := Capability{Kind: "agent", Name: "exploit"}
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "agent", Target: "exploit", Input: "go"}}},
	}}
	e, dw := voiGateEngine(llm, func(string) []Capability { return []Capability{exploit} })
	e.AddSystem(VoIGateSystem)

	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Tick() // both gates fire: a decision request and a plan request

	if n := dw.Drain(t.Context()); n != 0 || llm.calls != 0 {
		t.Fatalf("the Decider decided while the plan was in flight (processed %d, LLM calls %d)", n, llm.calls)
	}
	e.Tick()
	if ms := e.Missions(); len(ms) != 1 || ms[0].Status != MissionRunning {
		t.Fatalf("the mission must still run while it waits for the plan: %+v", ms)
	}

	approveViaVoI(e, "m1", exploit) // the plan lands
	e.Tick()
	if n := dw.Drain(t.Context()); n != 1 || llm.calls != 1 {
		t.Fatalf("the Decider did not decide after the plan landed (processed %d, LLM calls %d)", n, llm.calls)
	}
	e.Tick()

	var dispatched bool
	for _, wi := range e.Work() {
		if wi.MissionID == "m1" && wi.Target == "exploit" {
			dispatched = true
		}
	}
	if !dispatched {
		t.Fatalf("the dispatch for the covering capability did not pass the gate: %+v", e.Work())
	}
}
