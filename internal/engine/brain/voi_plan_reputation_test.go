// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"
)

// TestPlanVoI_NewHypothesisInheritsReputationPrior proves gibson#267 AC3: a new
// (unstaked) hypothesis of a technique with a track record starts from that
// technique×environment reputation as its prior P(claim valid), not the flat
// max-uncertainty default. No bet was placed, so this is a PRIOR, not a stake:
// HasStake stays false (Stake == neutral), while the confidence prior driving
// InfoGain is the technique's track record.
func TestPlanVoI_NewHypothesisInheritsReputationPrior(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()
	// A technique with a strong track record in this environment.
	if err := substrate.SetBelief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"),
		NodeBelief{Belief: Belief{Exploitable: 0.9}}); err != nil {
		t.Fatalf("SetBelief: %v", err)
	}

	in := VoIPlanInput{
		Hypotheses: []HypothesisSnapshot{{ID: 7, Claim: "c", ScopeID: "scope-a", Technique: "t1190"}},
		Tenant:     "acme",
	}
	got, err := PlanVoI(ctx, in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	c := got[0]
	if c.Stake != voiNeutralStakePrior {
		t.Fatalf("Stake = %v, want neutral %v (no bet placed — a prior is not a stake)", c.Stake, voiNeutralStakePrior)
	}
	// Connectivity is 0 (no references), so InfoGain == binaryEntropy(prior).
	// A raised prior of 0.9 yields a different InfoGain than the flat 0.5 default
	// (binaryEntropy(0.5) == 1.0), proving the reputation prior was used.
	if want := binaryEntropy(0.9); c.InfoGain != want {
		t.Fatalf("InfoGain = %v, want binaryEntropy(0.9) = %v (the raised reputation prior, not the 0.5 default)", c.InfoGain, want)
	}
}

// TestPlanVoI_UntrackedTechniqueKeepsNeutralPrior proves the AC3 default path:
// a hypothesis whose technique has no track record (or names none) keeps exactly
// today's behavior — the flat unstaked confidence and the neutral reputation
// multiplier.
func TestPlanVoI_UntrackedTechniqueKeepsNeutralPrior(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()

	in := VoIPlanInput{
		Hypotheses: []HypothesisSnapshot{{ID: 7, Claim: "c", ScopeID: "scope-a", Technique: "t-unknown"}},
		Tenant:     "acme",
	}
	got, err := PlanVoI(ctx, in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	c := got[0]
	if want := binaryEntropy(voiUnstakedConfidence); c.InfoGain != want {
		t.Fatalf("InfoGain = %v, want binaryEntropy(voiUnstakedConfidence) = %v (no track record → flat default)", c.InfoGain, want)
	}
	if c.Reputation != voiNeutralReputationPrior {
		t.Fatalf("Reputation = %v, want neutral %v (no track record → no penalty)", c.Reputation, voiNeutralReputationPrior)
	}
}

// TestPlanVoI_PursuitPriorityReflectsReputation proves gibson#267 AC4: of two
// otherwise-identical unstaked hypotheses, the one whose technique has the
// higher reputation ranks first. The two priors (0.9 and 0.1) have equal binary
// entropy, so InfoGain is identical for both — the reputation MULTIPLIER is what
// breaks the tie, exactly the "reputation raises pursuit priority" criterion.
func TestPlanVoI_PursuitPriorityReflectsReputation(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()
	if err := substrate.SetBelief(ctx, TechniqueEnvironmentRef("acme", "t-strong", "scope-a"),
		NodeBelief{Belief: Belief{Exploitable: 0.9}}); err != nil {
		t.Fatalf("SetBelief strong: %v", err)
	}
	if err := substrate.SetBelief(ctx, TechniqueEnvironmentRef("acme", "t-weak", "scope-a"),
		NodeBelief{Belief: Belief{Exploitable: 0.1}}); err != nil {
		t.Fatalf("SetBelief weak: %v", err)
	}

	in := VoIPlanInput{
		Hypotheses: []HypothesisSnapshot{
			{ID: 1, Claim: "weak", ScopeID: "scope-a", Technique: "t-weak"},
			{ID: 2, Claim: "strong", ScopeID: "scope-a", Technique: "t-strong"},
		},
		Tenant: "acme",
	}
	got, err := PlanVoI(ctx, in, substrate, ExactVoIScorer(), 0)
	if err != nil {
		t.Fatalf("PlanVoI: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	if got[0].RefID != "2" {
		t.Fatalf("got[0].RefID = %q, want the high-reputation technique's hypothesis (2) ranked first", got[0].RefID)
	}
	if got[0].Reputation != 0.9 || got[1].Reputation != 0.1 {
		t.Fatalf("reputation multipliers = %v, %v; want 0.9, 0.1", got[0].Reputation, got[1].Reputation)
	}
	if got[0].Value <= got[1].Value {
		t.Fatalf("high-reputation value %v must exceed low-reputation value %v", got[0].Value, got[1].Value)
	}
}
