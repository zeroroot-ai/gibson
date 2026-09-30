// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"math"
	"reflect"
	"testing"
)

func TestBinaryEntropy(t *testing.T) {
	tests := []struct {
		p    float64
		want float64
	}{
		{p: 0, want: 0},
		{p: 1, want: 0},
		{p: 0.5, want: 1}, // maximal uncertainty for a binary variable
		{p: -1, want: 0},  // out of range: treated as certain, never NaN
		{p: 2, want: 0},
	}
	for _, tc := range tests {
		if got := binaryEntropy(tc.p); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("binaryEntropy(%v) = %v, want %v", tc.p, got, tc.want)
		}
	}
	// Symmetric around 0.5.
	if a, b := binaryEntropy(0.2), binaryEntropy(0.8); math.Abs(a-b) > 1e-9 {
		t.Errorf("binaryEntropy(0.2)=%v, binaryEntropy(0.8)=%v, want equal (symmetric)", a, b)
	}
}

// TestExactVoIScorer_HighEntropyBeatsLowEntropy proves the core VoI intuition:
// a candidate whose confidence is near 0.5 (maximally uncertain — testing it
// resolves the most uncertainty) outranks one whose confidence already sits
// near 0 or 1 (little left to learn), all else equal.
func TestExactVoIScorer_HighEntropyBeatsLowEntropy(t *testing.T) {
	scorer := ExactVoIScorer()
	uncertain := scorer.Score(VoIScoreInput{
		Kind: VoICandidateEvidence, RefID: "uncertain", Confidence: 0.5, Reputation: 1,
	})
	confident := scorer.Score(VoIScoreInput{
		Kind: VoICandidateEvidence, RefID: "confident", Confidence: 0.95, Reputation: 1,
	})
	if uncertain.Value <= confident.Value {
		t.Fatalf("uncertain.Value=%v, confident.Value=%v, want uncertain to score higher", uncertain.Value, confident.Value)
	}
}

// TestExactVoIScorer_ConnectivityAmplifiesInfoGain proves the ADR-0026 §3
// "juiciness × connectivity" factor: a candidate touching more enablement
// edges (a more consequential node to resolve) scores higher for the SAME
// confidence, all else equal.
func TestExactVoIScorer_ConnectivityAmplifiesInfoGain(t *testing.T) {
	scorer := ExactVoIScorer()
	isolated := scorer.Score(VoIScoreInput{Kind: VoICandidateEvidence, RefID: "a", Confidence: 0.5, Connectivity: 0, Reputation: 1})
	connected := scorer.Score(VoIScoreInput{Kind: VoICandidateEvidence, RefID: "b", Confidence: 0.5, Connectivity: 5, Reputation: 1})
	if connected.Value <= isolated.Value {
		t.Fatalf("connected.Value=%v, isolated.Value=%v, want connected to score higher", connected.Value, isolated.Value)
	}
	// Zero connectivity must not zero the score out entirely (today's live
	// graph has no cross-host edges yet — see belief_graph_wire.go — so every
	// real evidence-move candidate currently has Connectivity=0).
	if isolated.Value <= 0 {
		t.Fatalf("isolated.Value = %v, want > 0 (connectivity=0 must not collapse the score)", isolated.Value)
	}
}

// TestExactVoIScorer_SurpriseAddsToValue proves the anomaly channel (ADR-0005
// §6/ADR-0006) is never curated away: a surprised candidate scores strictly
// higher than an otherwise-identical one that is not.
func TestExactVoIScorer_SurpriseAddsToValue(t *testing.T) {
	scorer := ExactVoIScorer()
	plain := scorer.Score(VoIScoreInput{Kind: VoICandidateEvidence, RefID: "a", Confidence: 0.5, Reputation: 1})
	surprised := scorer.Score(VoIScoreInput{Kind: VoICandidateEvidence, RefID: "a", Confidence: 0.5, Reputation: 1, Surprised: true})
	if surprised.Value <= plain.Value {
		t.Fatalf("surprised.Value=%v, plain.Value=%v, want surprised to score higher", surprised.Value, plain.Value)
	}
	if surprised.Surprise != surpriseBoost {
		t.Fatalf("Surprise = %v, want the shared surpriseBoost constant %v (reused, not reimplemented)", surprised.Surprise, surpriseBoost)
	}
}

// TestExactVoIScorer_UnstakedHypothesisIsNotPenalized proves ADR-0026 §6's
// optimism-under-uncertainty prior: a hypothesis nobody has bet on yet is
// scored as if fully staked (neutral prior), not zeroed out — VoI is what
// should DRIVE the first bet, not merely re-rank already-staked ones.
func TestExactVoIScorer_UnstakedHypothesisIsNotPenalized(t *testing.T) {
	scorer := ExactVoIScorer()
	unstaked := scorer.Score(VoIScoreInput{
		Kind: VoICandidateHypothesis, RefID: "h1", Confidence: voiUnstakedConfidence, Reputation: 1, HasStake: false,
	})
	if unstaked.Stake != voiNeutralStakePrior {
		t.Fatalf("Stake = %v, want the neutral prior %v", unstaked.Stake, voiNeutralStakePrior)
	}
	if unstaked.Value <= 0 {
		t.Fatalf("an unstaked hypothesis scored %v, want > 0 (must not be zeroed out)", unstaked.Value)
	}
}

// TestExactVoIScorer_StakedHypothesisUsesItsConfidence proves a hypothesis
// with a placed bet is weighted by that bet's confidence, not the neutral
// prior — "pursuing a hypothesis is placing a bet" (ADR-0029 §3).
func TestExactVoIScorer_StakedHypothesisUsesItsConfidence(t *testing.T) {
	scorer := ExactVoIScorer()
	got := scorer.Score(VoIScoreInput{
		Kind: VoICandidateHypothesis, RefID: "h1", Confidence: 0.9, Reputation: 1, HasStake: true,
	})
	if got.Stake != 0.9 {
		t.Fatalf("Stake = %v, want the staked confidence 0.9", got.Stake)
	}
}

// TestExactVoIScorer_ReputationScalesValue proves reputation is a genuine
// multiplier (ADR-0026 §3's "× reputation"), not a decorative field.
func TestExactVoIScorer_ReputationScalesValue(t *testing.T) {
	scorer := ExactVoIScorer()
	low := scorer.Score(VoIScoreInput{Kind: VoICandidateHypothesis, RefID: "h1", Confidence: 0.5, Reputation: 0.2, HasStake: true})
	high := scorer.Score(VoIScoreInput{Kind: VoICandidateHypothesis, RefID: "h1", Confidence: 0.5, Reputation: 2.0, HasStake: true})
	if high.Value <= low.Value {
		t.Fatalf("high-reputation.Value=%v, low-reputation.Value=%v, want high to score strictly more", high.Value, low.Value)
	}
}

// TestExactVoIScorer_HypothesisCostsMoreThanEvidence proves the two candidate
// kinds are on one scale but not identically costed: pursuing a hypothesis
// (an active probe/bet) costs more than gathering more evidence passively —
// ADR-0026 §2's "one scale", not "one cost".
func TestExactVoIScorer_HypothesisCostsMoreThanEvidence(t *testing.T) {
	scorer := ExactVoIScorer()
	evidence := scorer.Score(VoIScoreInput{Kind: VoICandidateEvidence, RefID: "a", Confidence: 0.5, Reputation: 1})
	hypothesis := scorer.Score(VoIScoreInput{Kind: VoICandidateHypothesis, RefID: "a", Confidence: 0.5, Reputation: 1, HasStake: true})
	if hypothesis.ResourceCost+hypothesis.RiskCost <= evidence.ResourceCost+evidence.RiskCost {
		t.Fatalf("hypothesis cost (%v+%v) <= evidence cost (%v+%v), want strictly more",
			hypothesis.ResourceCost, hypothesis.RiskCost, evidence.ResourceCost, evidence.RiskCost)
	}
}

// TestExactVoIScorer_DeterministicAndExact proves repeated scoring of the
// identical input is bit-identical — ADR-0026 §4/§5's "exact, deterministic"
// requirement, no sampling anywhere in this one-step scorer.
func TestExactVoIScorer_DeterministicAndExact(t *testing.T) {
	scorer := ExactVoIScorer()
	in := VoIScoreInput{Kind: VoICandidateHypothesis, RefID: "h1", Confidence: 0.73, Connectivity: 3, Surprised: true, HasStake: true, Reputation: 1.4}
	first := scorer.Score(in)
	for range 5 {
		// reflect.DeepEqual, not !=: VoICandidate carries a []Capability field
		// (CoveringCapabilities, ADR-0035/gibson#387), which is not comparable.
		if got := scorer.Score(in); !reflect.DeepEqual(got, first) {
			t.Fatalf("repeated Score(%+v) diverged: %+v vs %+v", in, got, first)
		}
	}
}
