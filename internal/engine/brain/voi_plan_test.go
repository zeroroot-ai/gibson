// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// TestAttackGraphDegree_CountsBothEndpoints proves connectivity counts an
// edge for both the node it leaves and the node it enters — "touching an
// enablement edge" either way makes a node more consequential to resolve.
func TestAttackGraphDegree_CountsBothEndpoints(t *testing.T) {
	graph := AttackGraph{
		Edges: []InfraEdge{
			{Type: "RESOLVES_TO", From: "a", To: "b"},
			{Type: "RESOLVES_TO", From: "b", To: "c"},
		},
	}
	got := attackGraphDegree(graph)
	want := map[string]int{"a": 1, "b": 2, "c": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attackGraphDegree = %v, want %v", got, want)
	}
}

// TestPlanVoI_RanksEvidenceCandidatesByValue proves hosts are turned into
// evidence-move candidates and ranked by descending value — the highest
// entropy (most uncertain) host comes first.
func TestPlanVoI_RanksEvidenceCandidatesByValue(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hosts := []HostSnapshot{
		{ID: 1, Belief: Belief{Juicy: 0.95}}, // low entropy: nearly certain
		{ID: 2, Belief: Belief{Juicy: 0.5}},  // max entropy
	}
	in := VoIPlanInput{Hosts: hosts, Tenant: "acme"}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	if got[0].RefID != HostNodeID(2) {
		t.Fatalf("got[0].RefID = %q, want the high-entropy host %q first", got[0].RefID, HostNodeID(2))
	}
	if got[0].Kind != VoICandidateEvidence {
		t.Fatalf("got[0].Kind = %q, want %q", got[0].Kind, VoICandidateEvidence)
	}
}

// TestPlanVoI_UnstakedHypothesisBecomesACandidate proves a hypothesis with no
// bet yet is still scored (using the unstaked/neutral priors), never skipped
// — VoI must be able to drive the FIRST bet.
func TestPlanVoI_UnstakedHypothesisBecomesACandidate(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	in := VoIPlanInput{
		Hypotheses: []HypothesisSnapshot{{ID: 7, Claim: "port 6443 is unauthenticated"}},
		Tenant:     "acme",
	}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	c := got[0]
	if c.Kind != VoICandidateHypothesis || c.RefID != "7" {
		t.Fatalf("candidate = %+v, want Kind=hypothesis RefID=7", c)
	}
	if c.Stake != voiNeutralStakePrior {
		t.Fatalf("Stake = %v, want the neutral prior %v (no bet placed yet)", c.Stake, voiNeutralStakePrior)
	}
}

// TestPlanVoI_StakedHypothesisReadsItsClaimNodeBelief proves a hypothesis
// with a placed bet (a claim-node belief already on the substrate, the same
// one harness.PlaceBet writes) is scored using that staked confidence, not
// the unstaked prior — reading through the SAME substrate the market view
// writes to, per ADR-0029 §3.
func TestPlanVoI_StakedHypothesisReadsItsClaimNodeBelief(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	ctx := context.Background()
	// Mirrors harness.claimNodeRef's tenant-scoped convention exactly:
	// NodeRef{Kind: NodeKindClaim, ID: tenant + "/" + hypothesisID}.
	ref := NodeRef{Kind: NodeKindClaim, ID: "acme/7"}
	if err := substrate.SetBelief(ctx, ref, NodeBelief{Belief: Belief{Exploitable: 0.85, Model: "bet:v1"}}); err != nil {
		t.Fatalf("SetBelief: %v", err)
	}

	in := VoIPlanInput{
		Hypotheses: []HypothesisSnapshot{{ID: 7, Claim: "port 6443 is unauthenticated"}},
		Tenant:     "acme",
	}
	got, err := PlanVoI(ctx, in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 || got[0].Stake != 0.85 {
		t.Fatalf("candidate = %+v, want Stake=0.85 (the placed bet's confidence)", got[0])
	}
}

// TestPlanVoI_TruncatesToTopK proves the "VoI gates to top-k" acceptance
// criterion structurally: more candidates than topK are dropped, keeping the
// highest-value ones.
func TestPlanVoI_TruncatesToTopK(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hosts := make([]HostSnapshot, 0, 5)
	for i := range uint64(5) {
		hosts = append(hosts, HostSnapshot{ID: i + 1, Belief: Belief{Juicy: 0.5}})
	}
	in := VoIPlanInput{Hosts: hosts, Tenant: "acme"}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 2)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want top-2 of 5", len(got))
	}
}

// TestPlanVoI_TopKZeroOrNegativeKeepsEverything mirrors the SliceOptions/
// AmbientProjection convention this package already uses: a non-positive
// bound means "no bound", not "keep nothing".
func TestPlanVoI_TopKZeroOrNegativeKeepsEverything(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hosts := []HostSnapshot{{ID: 1}, {ID: 2}, {ID: 3}}
	in := VoIPlanInput{Hosts: hosts, Tenant: "acme"}

	for _, k := range []int{0, -1} {
		got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), k)
		if err != nil {
			t.Fatalf("PlanVoI(topK=%d): %v", k, err)
		}
		if len(got) != 3 {
			t.Fatalf("PlanVoI(topK=%d) = %d candidates, want all 3", k, len(got))
		}
	}
}

// TestPlanVoI_ConnectivityFromTheGraph proves a host's Connectivity input
// comes from the real attack graph, not a constant.
func TestPlanVoI_ConnectivityFromTheGraph(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hosts := []HostSnapshot{{ID: 1, Belief: Belief{Juicy: 0.5}}, {ID: 2, Belief: Belief{Juicy: 0.5}}}
	graph := AttackGraph{Edges: []InfraEdge{
		{Type: "RESOLVES_TO", From: HostNodeID(1), To: HostNodeID(2)},
	}}
	in := VoIPlanInput{Hosts: hosts, Graph: graph, Tenant: "acme"}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	byRef := map[string]VoICandidate{}
	for _, c := range got {
		byRef[c.RefID] = c
	}
	if byRef[HostNodeID(1)].InfoGain == 0 || byRef[HostNodeID(1)].InfoGain != byRef[HostNodeID(2)].InfoGain {
		t.Fatalf("expected both endpoints to share equal, nonzero connectivity-amplified info gain: %+v", byRef)
	}
	// Same confidence (0.5) and same degree (1 each) -> identical InfoGain.
	unconnected, err := PlanVoI(context.Background(), VoIPlanInput{
		Hosts: []HostSnapshot{{ID: 1, Belief: Belief{Juicy: 0.5}}}, Tenant: "acme",
	}, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI (unconnected): %v", err)
	}
	if unconnected[0].InfoGain >= byRef[HostNodeID(1)].InfoGain {
		t.Fatalf("unconnected InfoGain=%v, want less than connected InfoGain=%v", unconnected[0].InfoGain, byRef[HostNodeID(1)].InfoGain)
	}
}

// TestPlanVoI_DeterministicAcrossInputOrder proves the ranking does not
// depend on the order hosts/hypotheses happen to be listed in — the same
// replay-safety property gibson#286/#287 hold their own outputs to.
func TestPlanVoI_DeterministicAcrossInputOrder(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hosts := []HostSnapshot{
		{ID: 1, Belief: Belief{Juicy: 0.3}},
		{ID: 2, Belief: Belief{Juicy: 0.5}},
		{ID: 3, Belief: Belief{Juicy: 0.7}},
	}
	reversed := make([]HostSnapshot, len(hosts))
	for i, h := range hosts {
		reversed[len(hosts)-1-i] = h
	}

	a, err := PlanVoI(context.Background(), VoIPlanInput{Hosts: hosts, Tenant: "acme"}, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	b, err := PlanVoI(context.Background(), VoIPlanInput{Hosts: reversed, Tenant: "acme"}, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI (reversed): %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("order-dependent result:\n got  %+v\n want %+v", b, a)
	}
}

// TestSortVoICandidates_TiesBrokenByKindThenRefID proves the total order:
// equal Value falls through to Kind, and equal Value+Kind falls through to
// RefID — never a coin flip (Go's sort is otherwise unspecified for ties).
func TestSortVoICandidates_TiesBrokenByKindThenRefID(t *testing.T) {
	c := []VoICandidate{
		{Kind: VoICandidateHypothesis, RefID: "z", Value: 1},
		{Kind: VoICandidateEvidence, RefID: "b", Value: 1},
		{Kind: VoICandidateEvidence, RefID: "a", Value: 1},
	}
	sortVoICandidates(c)
	want := []VoICandidate{
		{Kind: VoICandidateEvidence, RefID: "a", Value: 1},
		{Kind: VoICandidateEvidence, RefID: "b", Value: 1},
		{Kind: VoICandidateHypothesis, RefID: "z", Value: 1},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("sortVoICandidates = %+v, want %+v", c, want)
	}
}

// TestPlanVoI_PropagatesSubstrateError proves a belief-read failure surfaces
// as an error rather than silently treating the hypothesis as unstaked.
func TestPlanVoI_PropagatesSubstrateError(t *testing.T) {
	substrate := &erroringBeliefSubstrate{
		fakeBeliefSubstrate: newFakeBeliefSubstrate(),
		failBeliefFor:       NodeRef{Kind: NodeKindClaim, ID: "acme/7"},
	}
	in := VoIPlanInput{
		Hypotheses: []HypothesisSnapshot{{ID: 7}},
		Tenant:     "acme",
	}
	if _, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0); err == nil {
		t.Fatalf("PlanVoI did not propagate the substrate error")
	}
}

// TestResolveReputation_EmptyKeyIsTheNeutralPrior proves the "no resolvable
// technique×environment key yet" path (every candidate today) never touches
// the substrate at all.
func TestResolveReputation_EmptyKeyIsTheNeutralPrior(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	got, err := resolveReputation(context.Background(), substrate, "")
	if err != nil {
		t.Fatalf("resolveReputation: %v", err)
	}
	if got != voiNeutralReputationPrior {
		t.Fatalf("got %v, want the neutral prior %v", got, voiNeutralReputationPrior)
	}
}

// TestResolveReputation_ReadsTechniqueEnvironmentBelief proves the seam a
// future candidate carrying a real technique×environment key will use: a
// recorded belief on that key's NodeKindTechniqueEnvironment node is read and
// returned as-is (ADR-0029 §3's "P(technique works here)").
func TestResolveReputation_ReadsTechniqueEnvironmentBelief(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	ctx := context.Background()
	ref := NodeRef{Kind: NodeKindTechniqueEnvironment, ID: "cve-2024-1234@host-class-a"}
	if err := substrate.SetBelief(ctx, ref, NodeBelief{Belief: Belief{Exploitable: 0.42}}); err != nil {
		t.Fatalf("SetBelief: %v", err)
	}
	got, err := resolveReputation(ctx, substrate, "cve-2024-1234@host-class-a")
	if err != nil {
		t.Fatalf("resolveReputation: %v", err)
	}
	if got != 0.42 {
		t.Fatalf("got %v, want the recorded reputation 0.42", got)
	}
}

// TestResolveReputation_UnknownKeyIsTheNeutralPrior proves a technique×
// environment key with no recorded belief yet also resolves to the neutral
// prior — no data means "do not penalize" (ADR-0026 §6), same as an empty key.
func TestResolveReputation_UnknownKeyIsTheNeutralPrior(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	got, err := resolveReputation(context.Background(), substrate, "never-recorded")
	if err != nil {
		t.Fatalf("resolveReputation: %v", err)
	}
	if got != voiNeutralReputationPrior {
		t.Fatalf("got %v, want the neutral prior %v", got, voiNeutralReputationPrior)
	}
}

// TestResolveReputation_PropagatesSubstrateError proves a belief-read failure
// on a technique×environment lookup surfaces as an error.
func TestResolveReputation_PropagatesSubstrateError(t *testing.T) {
	ref := NodeRef{Kind: NodeKindTechniqueEnvironment, ID: "boom"}
	substrate := &erroringBeliefSubstrate{fakeBeliefSubstrate: newFakeBeliefSubstrate(), failBeliefFor: ref}
	if _, err := resolveReputation(context.Background(), substrate, "boom"); err == nil {
		t.Fatalf("resolveReputation did not propagate the substrate error")
	}
}

// ---------------------------------------------------------------------------
// PlanVoI's technique -> capability bridge (ADR-0035 decision 4, gibson#387):
// a hypothesis candidate's Technique is resolved against VoIPlanInput's
// Capabilities/Hierarchy into CoveringCapabilities.
// ---------------------------------------------------------------------------

// TestPlanVoI_HypothesisCandidateResolvesCoveringCapabilities proves a
// hypothesis's Technique carries onto its candidate and resolves the
// capabilities whose declared Coverage matches it via the taxonomy category
// rollup — the consumer that ties #385 (Hypothesis.Technique) and #386
// (Capability.Coverage) together.
func TestPlanVoI_HypothesisCandidateResolvesCoveringCapabilities(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hierarchy := dispatchTestHierarchy(t)
	generalist := Capability{Kind: "agent", Name: "injection-hunter",
		Coverage: dispatchCoverage(t, hierarchy, []taxonomy.CategoryID{"prompt_injection"}, nil)}
	unrelated := Capability{Kind: "tool", Name: "port-scanner", Coverage: taxonomy.EmptyCoverage()}

	in := VoIPlanInput{
		Hypotheses:   []HypothesisSnapshot{{ID: 7, Claim: "the prompt filter is bypassable", Technique: "indirect_prompt_injection"}},
		Tenant:       "acme",
		Capabilities: []Capability{generalist, unrelated},
		Hierarchy:    hierarchy,
	}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	c := got[0]
	if c.Technique != "indirect_prompt_injection" {
		t.Fatalf("Technique = %q, want %q", c.Technique, "indirect_prompt_injection")
	}
	if len(c.CoveringCapabilities) != 1 || c.CoveringCapabilities[0].Name != "injection-hunter" {
		t.Fatalf("CoveringCapabilities = %+v, want only %q (via the category rollup)", c.CoveringCapabilities, "injection-hunter")
	}
}

// TestPlanVoI_HypothesisWithNoTechniqueResolvesNoCoveringCapabilities proves
// gibson#387's "no covering capability handled explicitly" acceptance
// criterion at the PlanVoI level: a hypothesis that never had a technique set
// resolves an empty CoveringCapabilities, even with a non-empty catalog, and
// PlanVoI does not error.
func TestPlanVoI_HypothesisWithNoTechniqueResolvesNoCoveringCapabilities(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hierarchy := dispatchTestHierarchy(t)
	generalist := Capability{Kind: "agent", Name: "injection-hunter",
		Coverage: dispatchCoverage(t, hierarchy, []taxonomy.CategoryID{"prompt_injection"}, nil)}

	in := VoIPlanInput{
		Hypotheses:   []HypothesisSnapshot{{ID: 7, Claim: "no technique named"}},
		Tenant:       "acme",
		Capabilities: []Capability{generalist},
		Hierarchy:    hierarchy,
	}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 || got[0].Technique != "" || len(got[0].CoveringCapabilities) != 0 {
		t.Fatalf("candidate = %+v, want Technique=\"\" and no covering capabilities", got[0])
	}
}

// TestPlanVoI_EvidenceCandidateNeverResolvesCoveringCapabilities proves an
// evidence-move candidate (a Host, not a Hypothesis) always carries an empty
// Technique and CoveringCapabilities — a bare evidence move names no
// technique (the same convention resolveReputation already documents), so it
// has nothing to gate against even with a populated catalog.
func TestPlanVoI_EvidenceCandidateNeverResolvesCoveringCapabilities(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	hierarchy := dispatchTestHierarchy(t)
	generalist := Capability{Kind: "agent", Name: "injection-hunter",
		Coverage: dispatchCoverage(t, hierarchy, []taxonomy.CategoryID{"prompt_injection"}, nil)}

	in := VoIPlanInput{
		Hosts:        []HostSnapshot{{ID: 1, Belief: Belief{Juicy: 0.5}}},
		Tenant:       "acme",
		Capabilities: []Capability{generalist},
		Hierarchy:    hierarchy,
	}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 || got[0].Technique != "" || len(got[0].CoveringCapabilities) != 0 {
		t.Fatalf("candidate = %+v, want Technique=\"\" and no covering capabilities", got[0])
	}
}

// TestPlanVoI_NoHierarchySuppliedNeverPanics proves an unset Hierarchy (the
// zero VoIPlanInput's default, and today's only daemon-wired shape — see
// belief_provider.go's wireBrainRegistry) is handled explicitly: no candidate
// resolves a covering capability, and PlanVoI never panics or errors.
func TestPlanVoI_NoHierarchySuppliedNeverPanics(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	in := VoIPlanInput{
		Hypotheses: []HypothesisSnapshot{{ID: 7, Claim: "c", Technique: "indirect_prompt_injection"}},
		Tenant:     "acme",
	}

	got, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 || len(got[0].CoveringCapabilities) != 0 {
		t.Fatalf("candidate = %+v, want no covering capabilities (no hierarchy supplied)", got[0])
	}
}
