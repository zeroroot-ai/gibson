// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"math"
	"testing"
	"time"
)

// setClaimBelief stakes a predicted probability p on hypothesisID's claim
// node, mirroring harness.PlaceBet's own tenant+"/"+hypothesisID convention
// exactly (callback_place_bet.go's claimNodeRef, unexported in a different
// package — duplicated here as a plain literal rather than a shared helper,
// same as ComputeCalibration itself does).
func setClaimBelief(t *testing.T, substrate BeliefSubstrate, tenant, hypothesisID string, p float64) {
	t.Helper()
	ref := NodeRef{Kind: NodeKindClaim, ID: tenant + "/" + hypothesisID}
	if err := substrate.SetBelief(context.Background(), ref, NodeBelief{Belief: Belief{Exploitable: p}}); err != nil {
		t.Fatalf("SetBelief: %v", err)
	}
}

func approxEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestComputeCalibration_EmptyInputIsAllZeroNotError proves an empty
// settlement set is a valid, well-formed (if empty) report rather than an
// error — a fresh tenant with no settled bets yet.
func TestComputeCalibration_EmptyInputIsAllZeroNotError(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	report, err := ComputeCalibration(context.Background(), "acme", nil, substrate, 0)
	if err != nil {
		t.Fatalf("ComputeCalibration: %v", err)
	}
	if report.Tenant != "acme" || report.Overall.N != 0 || len(report.ByTechnique) != 0 || report.Unscored != 0 {
		t.Fatalf("report = %+v, want an empty report for acme", report)
	}
	if len(report.Overall.Bins) != DefaultCalibrationBins {
		t.Fatalf("got %d bins, want the default %d", len(report.Overall.Bins), DefaultCalibrationBins)
	}
}

// TestComputeCalibration_ReadsThePredictedProbabilityFromTheClaimNode proves
// the predicted P comes from the SAME BeliefSubstrate claim-node belief
// harness.PlaceBet writes (NodeKindClaim, tenant+"/"+hypothesisID) — not a
// field on BetSettlement itself (which never carries a predicted probability).
func TestComputeCalibration_ReadsThePredictedProbabilityFromTheClaimNode(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	setClaimBelief(t, substrate, "acme", "h1", 0.8)
	settlements := []BetSettlementSnapshot{
		{HypothesisID: "h1", Verdict: SettlementVerdictTrue, Technique: "ssh_bruteforce"},
	}

	report, err := ComputeCalibration(context.Background(), "acme", settlements, substrate, 10)
	if err != nil {
		t.Fatalf("ComputeCalibration: %v", err)
	}
	if report.Overall.N != 1 || !approxEqual(report.Overall.MeanPredicted, 0.8) {
		t.Fatalf("Overall = %+v, want N=1 MeanPredicted=0.8", report.Overall)
	}
	if !approxEqual(report.Overall.ObservedFrequency, 1.0) {
		t.Fatalf("ObservedFrequency = %v, want 1.0 (the bet settled TRUE)", report.Overall.ObservedFrequency)
	}
	wantBrier := (0.8 - 1.0) * (0.8 - 1.0)
	if !approxEqual(report.Overall.BrierScore, wantBrier) {
		t.Fatalf("BrierScore = %v, want %v", report.Overall.BrierScore, wantBrier)
	}
}

// TestComputeCalibration_UnscoredWhenNoPredictionWasEverStaked proves a
// settled bet with no recorded claim-node belief (no PlaceBet call happened
// for it — e.g. a directly-settled test fixture, or a future settlement path
// that bypasses the market view) is excluded from every aggregate rather
// than silently treated as some default confidence, and is counted so the
// gap is visible, not hidden.
func TestComputeCalibration_UnscoredWhenNoPredictionWasEverStaked(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	settlements := []BetSettlementSnapshot{
		{HypothesisID: "never-staked", Verdict: SettlementVerdictTrue, Technique: "ssh_bruteforce"},
	}

	report, err := ComputeCalibration(context.Background(), "acme", settlements, substrate, 10)
	if err != nil {
		t.Fatalf("ComputeCalibration: %v", err)
	}
	if report.Unscored != 1 {
		t.Fatalf("Unscored = %d, want 1", report.Unscored)
	}
	if report.Overall.N != 0 || len(report.ByTechnique) != 0 {
		t.Fatalf("report = %+v, want the unscored settlement excluded from every aggregate", report)
	}
}

// TestComputeCalibration_FalseVerdictsHaveNoTechniqueAndAreOverallOnly proves
// today's real data-model gap explicitly: BetSettlement only carries
// Technique for a TRUE verdict (bet_settlement.go, gibson#279's FALSE path
// has no Technique field at all). A FALSE-settled, staked bet still counts
// toward the tenant-wide Overall calibration (a miss is real, recorded
// evidence — ADR-0023, never silence) but cannot be attributed to any
// technique bucket, since none is known.
func TestComputeCalibration_FalseVerdictsHaveNoTechniqueAndAreOverallOnly(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	setClaimBelief(t, substrate, "acme", "h1", 0.3)
	settlements := []BetSettlementSnapshot{
		{HypothesisID: "h1", Verdict: SettlementVerdictFalse, Reason: "exhausted"}, // Technique == ""
	}

	report, err := ComputeCalibration(context.Background(), "acme", settlements, substrate, 10)
	if err != nil {
		t.Fatalf("ComputeCalibration: %v", err)
	}
	if report.Overall.N != 1 || !approxEqual(report.Overall.ObservedFrequency, 0) {
		t.Fatalf("Overall = %+v, want the FALSE settlement counted (N=1, ObservedFrequency=0)", report.Overall)
	}
	if len(report.ByTechnique) != 0 {
		t.Fatalf("ByTechnique = %+v, want empty (no technique known for this settlement)", report.ByTechnique)
	}
}

// TestComputeCalibration_GroupsByTechniqueSortedAlphabetically proves
// ByTechnique is a genuine per-technique breakdown, deterministically
// ordered regardless of settlement input order.
func TestComputeCalibration_GroupsByTechniqueSortedAlphabetically(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	setClaimBelief(t, substrate, "acme", "h1", 0.9)
	setClaimBelief(t, substrate, "acme", "h2", 0.4)
	settlements := []BetSettlementSnapshot{
		{HypothesisID: "h1", Verdict: SettlementVerdictTrue, Technique: "zeta_technique"},
		{HypothesisID: "h2", Verdict: SettlementVerdictFalse, Technique: "alpha_technique"},
	}

	report, err := ComputeCalibration(context.Background(), "acme", settlements, substrate, 10)
	if err != nil {
		t.Fatalf("ComputeCalibration: %v", err)
	}
	if len(report.ByTechnique) != 2 {
		t.Fatalf("got %d technique groups, want 2", len(report.ByTechnique))
	}
	if report.ByTechnique[0].Technique != "alpha_technique" || report.ByTechnique[1].Technique != "zeta_technique" {
		t.Fatalf("ByTechnique order = [%q, %q], want alphabetical", report.ByTechnique[0].Technique, report.ByTechnique[1].Technique)
	}
	if report.Overall.N != 2 {
		t.Fatalf("Overall.N = %d, want 2 (both settlements, regardless of technique grouping)", report.Overall.N)
	}
}

// TestComputeCalibration_WellCalibratedTechnique is the "does 0.8 mean 80% in
// reality" acceptance test in miniature: 10 bets on one technique, all
// predicted 0.8, 8 settled TRUE and 2 FALSE — a textbook well-calibrated
// technique. MeanPredicted and ObservedFrequency should coincide.
func TestComputeCalibration_WellCalibratedTechnique(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	var settlements []BetSettlementSnapshot
	for i := range 10 {
		id := "h" + string(rune('a'+i))
		setClaimBelief(t, substrate, "acme", id, 0.8)
		verdict := SettlementVerdictTrue
		if i >= 8 {
			verdict = SettlementVerdictFalse
		}
		settlements = append(settlements, BetSettlementSnapshot{HypothesisID: id, Verdict: verdict, Technique: "sqli"})
	}

	report, err := ComputeCalibration(context.Background(), "acme", settlements, substrate, 10)
	if err != nil {
		t.Fatalf("ComputeCalibration: %v", err)
	}
	if len(report.ByTechnique) != 1 {
		t.Fatalf("got %d technique groups, want 1", len(report.ByTechnique))
	}
	tc := report.ByTechnique[0]
	if !approxEqual(tc.MeanPredicted, 0.8) {
		t.Fatalf("MeanPredicted = %v, want 0.8", tc.MeanPredicted)
	}
	if !approxEqual(tc.ObservedFrequency, 0.8) {
		t.Fatalf("ObservedFrequency = %v, want 0.8 (8/10 settled TRUE) — well calibrated", tc.ObservedFrequency)
	}
	// The bin containing 0.8 should hold all 10 points.
	bin := tc.Bins[calibrationBinIndex(0.8, 10)]
	if bin.N != 10 {
		t.Fatalf("bin containing 0.8 has N=%d, want 10", bin.N)
	}
}

// TestCalibrationBinIndex_EdgeCases proves p==1.0 lands in the last bin
// rather than out of range, and p==0.0 lands in the first.
func TestCalibrationBinIndex_EdgeCases(t *testing.T) {
	if got := calibrationBinIndex(1.0, 10); got != 9 {
		t.Fatalf("calibrationBinIndex(1.0, 10) = %d, want 9", got)
	}
	if got := calibrationBinIndex(0.0, 10); got != 0 {
		t.Fatalf("calibrationBinIndex(0.0, 10) = %d, want 0", got)
	}
	if got := calibrationBinIndex(0.95, 10); got != 9 {
		t.Fatalf("calibrationBinIndex(0.95, 10) = %d, want 9", got)
	}
}

// TestComputeCalibration_NonPositiveBinsUsesDefault proves numBins <= 0 falls
// back to DefaultCalibrationBins rather than producing a zero-length or
// panicking bin slice.
func TestComputeCalibration_NonPositiveBinsUsesDefault(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	for _, n := range []int{0, -1} {
		report, err := ComputeCalibration(context.Background(), "acme", nil, substrate, n)
		if err != nil {
			t.Fatalf("ComputeCalibration(numBins=%d): %v", n, err)
		}
		if len(report.Overall.Bins) != DefaultCalibrationBins {
			t.Fatalf("ComputeCalibration(numBins=%d) got %d bins, want the default %d", n, len(report.Overall.Bins), DefaultCalibrationBins)
		}
	}
}

// TestComputeCalibration_PropagatesSubstrateError proves a belief-read
// failure surfaces as an error rather than silently treating the bet as
// unscored.
func TestComputeCalibration_PropagatesSubstrateError(t *testing.T) {
	ref := NodeRef{Kind: NodeKindClaim, ID: "acme/h1"}
	substrate := &erroringBeliefSubstrate{fakeBeliefSubstrate: newFakeBeliefSubstrate(), failBeliefFor: ref}
	settlements := []BetSettlementSnapshot{{HypothesisID: "h1", Verdict: SettlementVerdictTrue, Technique: "sqli"}}

	if _, err := ComputeCalibration(context.Background(), "acme", settlements, substrate, 10); err == nil {
		t.Fatalf("ComputeCalibration did not propagate the substrate error")
	}
}

// TestEngine_Calibration_ReadsLiveSettledBets proves the Engine.Calibration
// accessor wires the engine's OWN current tenant and settled bets into
// ComputeCalibration correctly, against a real, ticking Engine (not just the
// pure function directly). It uses a fakeBeliefSubstrate rather than
// WorldBeliefSubstrate: WorldBeliefSubstrate does not back Claim nodes yet
// (belief_world_substrate.go's own doc comment — "a substrate for those
// views is separate, later work"), the same gap harness.PlaceBet's live
// wiring has today; this accessor is substrate-agnostic and will read
// whichever Claim substrate the daemon eventually wires, unchanged.
func TestEngine_Calibration_ReadsLiveSettledBets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e := NewRegistry(ctx).For("acme")

	substrate := newFakeBeliefSubstrate()
	setClaimBelief(t, substrate, "acme", "h1", 0.7)
	e.Submit(BetSettledTrue{HypothesisID: "h1", Technique: "sqli"})

	deadline := time.Now().Add(2 * time.Second)
	var report CalibrationReport
	for time.Now().Before(deadline) {
		var err error
		report, err = e.Calibration(ctx, substrate, 0)
		if err != nil {
			t.Fatalf("Calibration: %v", err)
		}
		if report.Overall.N == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if report.Tenant != "acme" || report.Overall.N != 1 {
		t.Fatalf("report = %+v, want Tenant=acme Overall.N=1", report)
	}
	if len(report.ByTechnique) != 1 || report.ByTechnique[0].Technique != "sqli" {
		t.Fatalf("ByTechnique = %+v, want one sqli group", report.ByTechnique)
	}
}

// TestComputeCalibration_DeterministicAcrossInputOrder proves the report does
// not depend on settlement input order — AC3's "deterministic; recomputable
// from the Timeline" (the Timeline's fold order is fixed, but this proves the
// aggregation itself does not introduce order-sensitivity beyond that).
func TestComputeCalibration_DeterministicAcrossInputOrder(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	setClaimBelief(t, substrate, "acme", "h1", 0.9)
	setClaimBelief(t, substrate, "acme", "h2", 0.4)
	setClaimBelief(t, substrate, "acme", "h3", 0.6)
	forward := []BetSettlementSnapshot{
		{HypothesisID: "h1", Verdict: SettlementVerdictTrue, Technique: "sqli"},
		{HypothesisID: "h2", Verdict: SettlementVerdictFalse, Technique: "sqli"},
		{HypothesisID: "h3", Verdict: SettlementVerdictTrue, Technique: "xss"},
	}
	reversed := []BetSettlementSnapshot{forward[2], forward[1], forward[0]}

	a, err := ComputeCalibration(context.Background(), "acme", forward, substrate, 10)
	if err != nil {
		t.Fatalf("ComputeCalibration: %v", err)
	}
	b, err := ComputeCalibration(context.Background(), "acme", reversed, substrate, 10)
	if err != nil {
		t.Fatalf("ComputeCalibration (reversed): %v", err)
	}
	if !approxEqual(a.Overall.MeanPredicted, b.Overall.MeanPredicted) ||
		!approxEqual(a.Overall.ObservedFrequency, b.Overall.ObservedFrequency) ||
		!approxEqual(a.Overall.BrierScore, b.Overall.BrierScore) {
		t.Fatalf("order-dependent Overall result: %+v vs %+v", a.Overall, b.Overall)
	}
	if len(a.ByTechnique) != len(b.ByTechnique) {
		t.Fatalf("order-dependent ByTechnique length: %d vs %d", len(a.ByTechnique), len(b.ByTechnique))
	}
	for i := range a.ByTechnique {
		if a.ByTechnique[i].Technique != b.ByTechnique[i].Technique {
			t.Fatalf("order-dependent ByTechnique[%d]: %q vs %q", i, a.ByTechnique[i].Technique, b.ByTechnique[i].Technique)
		}
	}
}
