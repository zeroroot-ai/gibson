// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"testing"
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
