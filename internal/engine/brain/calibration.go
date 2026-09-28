// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"sort"
)

// calibration.go is gibson#284: the reliability/calibration metric
// (ADR-0022, ADR-0006) — "does 0.8 mean 80% in reality?" — the number that
// answers a skeptic. It is pure read-side aggregation over two views that
// already exist and are independently owned:
//
//   - BetSettlementSnapshot (bet_settlement.go, Lane C's gibson#278/#279,
//     and gibson#280 next) — the OBSERVED outcome of a settled bet
//     (true/false), keyed by HypothesisID.
//   - the claim-node belief on BeliefSubstrate (belief_substrate.go,
//     NodeKindClaim, keyed "<tenant>/<hypothesisID>") — the PREDICTED
//     probability the fleet staked on that hypothesis when harness.PlaceBet
//     recorded it (bet_settlement.go's own doc comment already names this
//     as the reconciliation this file performs: "reconciling 'confidence'
//     and 'settled' into one substrate is left for a later slice" — this
//     is that slice, done read-side rather than by merging the two stores).
//
// This file never writes to either store, and never touches Lane C's
// settlement handlers (bet_settlement.go) or the belief-provider daemon
// wiring — it only reads BetSettlementSnapshot and BeliefSubstrate.Belief.
// It is deterministic and recomputable from the Timeline (AC3): both inputs
// are themselves pure folds of the Timeline, and this file's own
// aggregation introduces no additional state or randomness — the same
// settled bets and the same substrate contents always produce the same
// report, regardless of input order (TestComputeCalibration_
// DeterministicAcrossInputOrder).
//
// Known data-model gap, surfaced rather than hidden: BetSettlement only
// records Technique for a TRUE verdict (bet_settlement.go's own comment:
// "Set only for SettlementVerdictTrue"); gibson#279's FALSE path
// (BetExhaustionRequest) carries no technique at all. A FALSE-settled bet
// therefore still counts toward the tenant-wide Overall calibration (a miss
// is real, recorded evidence, ADR-0023 — never dropped) but cannot be
// attributed to any technique's own bucket, since none is recorded. Once a
// technique is threaded onto the FALSE path (a Lane C concern, not this
// file's), it flows through unchanged — the grouping key is simply
// BetSettlementSnapshot.Technique, read as-is.
//
// Exposure via a daemon API (the issue's second acceptance criterion) is
// deliberately left to a follow-up: ComputeCalibration and Engine.
// Calibration are the whole surface a daemon handler needs to call, but
// adding the actual RPC means a new proto (there is no existing analytics/
// metrics service to extend — IntelligenceService was retired) and a full
// authz-registry regen, both cross-cutting and best done once, not
// speculatively from this read-side slice while four other lanes are
// actively landing daemon-adjacent PRs in parallel.

// DefaultCalibrationBins is the number of equal-width probability buckets
// ComputeCalibration uses when the caller does not need a different
// resolution — deciles, the conventional reliability-diagram granularity.
const DefaultCalibrationBins = 10

// CalibrationBin is one predicted-probability bucket of a reliability
// diagram: every settled, staked bet whose predicted P fell in [Low, High)
// (the last bin is closed: [Low, High]), and the mean predicted probability
// vs the observed frequency of a TRUE verdict among them.
type CalibrationBin struct {
	Low, High         float64
	N                 int
	MeanPredicted     float64
	ObservedFrequency float64
}

// TechniqueCalibration is the reliability/calibration measure for one group
// of settled, staked bets: either every settled bet in the tenant
// (CalibrationReport.Overall, Technique == "") or one specific technique's
// settled bets (CalibrationReport.ByTechnique).
type TechniqueCalibration struct {
	Technique         string
	N                 int
	MeanPredicted     float64
	ObservedFrequency float64
	// BrierScore is the mean squared error between each bet's predicted
	// probability and its observed outcome (0 or 1) — the standard proper
	// scoring rule for calibration (0 is perfect; lower is better). Note a
	// well-calibrated technique with genuine uncertainty still has a
	// nonzero Brier score — perfect MeanPredicted/ObservedFrequency
	// agreement is not the same claim as zero error on every individual bet.
	BrierScore float64
	Bins       []CalibrationBin
}

// CalibrationReport is gibson#284's full reliability answer for one tenant:
// the tenant-wide aggregate, the per-technique breakdown, and how many
// settled bets could not be scored at all.
type CalibrationReport struct {
	Tenant      string
	Overall     TechniqueCalibration
	ByTechnique []TechniqueCalibration
	// Unscored counts settled bets with no recorded claim-node belief (no
	// PlaceBet-equivalent stake was ever recorded for that HypothesisID) —
	// excluded from every aggregate because calibration cannot compare a
	// predicted probability that was never staked. Surfaced, not hidden.
	Unscored int
}

type calibrationPoint struct {
	predicted float64
	observed  float64
}

// ComputeCalibration reads substrate's claim-node belief for every
// settlement's HypothesisID (tenant + "/" + HypothesisID, the same
// convention harness.PlaceBet writes — see file doc comment) and folds the
// result into tenant's CalibrationReport. numBins <= 0 uses
// DefaultCalibrationBins.
func ComputeCalibration(
	ctx context.Context,
	tenant string,
	settlements []BetSettlementSnapshot,
	substrate BeliefSubstrate,
	numBins int,
) (CalibrationReport, error) {
	if numBins <= 0 {
		numBins = DefaultCalibrationBins
	}

	overall := make([]calibrationPoint, 0, len(settlements))
	byTechnique := map[string][]calibrationPoint{}
	unscored := 0

	for _, s := range settlements {
		ref := NodeRef{Kind: NodeKindClaim, ID: tenant + "/" + s.HypothesisID}
		nb, ok, err := substrate.Belief(ctx, ref)
		if err != nil {
			return CalibrationReport{}, fmt.Errorf("calibration: read predicted probability for hypothesis %q: %w", s.HypothesisID, err)
		}
		if !ok {
			unscored++
			continue
		}

		observed := 0.0
		if s.Verdict == SettlementVerdictTrue {
			observed = 1.0
		}
		point := calibrationPoint{predicted: nb.Belief.Exploitable, observed: observed}

		overall = append(overall, point)
		if s.Technique != "" {
			byTechnique[s.Technique] = append(byTechnique[s.Technique], point)
		}
	}

	techniques := make([]string, 0, len(byTechnique))
	for technique := range byTechnique {
		techniques = append(techniques, technique)
	}
	sort.Strings(techniques)

	byTechniqueOut := make([]TechniqueCalibration, 0, len(techniques))
	for _, technique := range techniques {
		byTechniqueOut = append(byTechniqueOut, summarizeCalibration(technique, byTechnique[technique], numBins))
	}

	return CalibrationReport{
		Tenant:      tenant,
		Overall:     summarizeCalibration("", overall, numBins),
		ByTechnique: byTechniqueOut,
		Unscored:    unscored,
	}, nil
}

// summarizeCalibration reduces points into one TechniqueCalibration: the
// tenant/technique-wide summary stats plus the binned reliability curve.
func summarizeCalibration(technique string, points []calibrationPoint, numBins int) TechniqueCalibration {
	tc := TechniqueCalibration{Technique: technique, N: len(points), Bins: emptyCalibrationBins(numBins)}
	if len(points) == 0 {
		return tc
	}

	var sumPredicted, sumObserved, sumSquaredError float64
	binPredictedSum := make([]float64, numBins)
	binObservedSum := make([]float64, numBins)
	binN := make([]int, numBins)

	for _, p := range points {
		sumPredicted += p.predicted
		sumObserved += p.observed
		diff := p.predicted - p.observed
		sumSquaredError += diff * diff

		bin := calibrationBinIndex(p.predicted, numBins)
		binPredictedSum[bin] += p.predicted
		binObservedSum[bin] += p.observed
		binN[bin]++
	}

	n := float64(len(points))
	tc.MeanPredicted = sumPredicted / n
	tc.ObservedFrequency = sumObserved / n
	tc.BrierScore = sumSquaredError / n

	for i := range tc.Bins {
		if binN[i] == 0 {
			continue
		}
		tc.Bins[i].N = binN[i]
		tc.Bins[i].MeanPredicted = binPredictedSum[i] / float64(binN[i])
		tc.Bins[i].ObservedFrequency = binObservedSum[i] / float64(binN[i])
	}
	return tc
}

// emptyCalibrationBins returns numBins equal-width [Low, High) buckets
// spanning [0, 1], all zero-count — the shape a caller (a reliability
// diagram) can render even before any data has landed in a bucket.
func emptyCalibrationBins(numBins int) []CalibrationBin {
	bins := make([]CalibrationBin, numBins)
	for i := range bins {
		bins[i] = CalibrationBin{
			Low:  float64(i) / float64(numBins),
			High: float64(i+1) / float64(numBins),
		}
	}
	return bins
}

// calibrationBinIndex returns which of numBins equal-width buckets p falls
// into. p == 1.0 (and any defensive out-of-range p, which should never
// occur — every belief probability in this codebase is constructed in
// [0, 1]) is floored into the last bin rather than overflowing it.
func calibrationBinIndex(p float64, numBins int) int {
	idx := int(p * float64(numBins))
	if idx >= numBins {
		idx = numBins - 1
	}
	if idx < 0 {
		idx = 0
	}
	return idx
}

// Calibration computes the engine's tenant-wide reliability/calibration
// report from its current settled bets (BetSettlements) and substrate's
// claim-node beliefs — the read-only accessor a daemon handler calls to
// serve gibson#284's dashboard surface (see file doc comment for the
// current proto-exposure scope decision). substrate is typically a
// WorldBeliefSubstrate bound to this same engine.
func (e *Engine) Calibration(ctx context.Context, substrate BeliefSubstrate, numBins int) (CalibrationReport, error) {
	return ComputeCalibration(ctx, e.World.Tenant, e.BetSettlements(), substrate, numBins)
}
