// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// bet_scoring.go is gibson#277: score a settled bet under a proper scoring
// rule (ADR-0022) — the CALIBRATION/reliability signal ("does 0.8 mean 80%?"),
// the same rule B's read-side reliability metric reports in aggregate
// (calibration.go, gibson#284, TechniqueCalibration.BrierScore is the mean of
// exactly the per-bet values this file computes).
//
// The Brier score is NOT a braintrain training input, and must not become one:
// the offline trainer learns from OUTCOMES, not from scores — Beta-Bernoulli
// over recorded (evidence → outcome) rows and per-edge-type outcomes
// (braintrain/train.go, braintrain/edge_posterior.go), never a squared-error
// score. The settled-bet learning loop is reputation (gibson#267): a settled
// bet updates its technique×environment reputation (reputation_worker.go),
// which feeds new hypotheses' priors and the fleet's pursuit priority. Emitting
// the score as a second "settled-bet → training row" path would be a forbidden
// parallel codepath (ADR-0027) duplicating that loop. Scoring here answers "how
// well-calibrated was the stake", a separate question from "what to learn".
//
// The score is computed HERE, at settlement time, from the confidence the
// caller declares was staked (BetSettlement.PredictedProbability) and the
// verdict the settlement itself just decided — never read back from
// BeliefSubstrate. BeliefSubstrate is still an unbacked stub with no replay
// story of its own (bet_settlement.go's own package doc already notes
// this), so a score that depended on it could drift or fail to reproduce
// across a replay. Reduce never recomputes the score: it is computed once,
// in the Engine.SettleBetX orchestrator (bet_settlement.go), and carried on
// the settlement event as already-decided data — the same "evaluate once,
// fold the fact" rule every settlement event in this file already follows
// for EvidenceDigest. This is what makes scoring replayable (gibson#277
// AC3): replaying the Timeline re-applies the recorded score, it never
// rescores anything.
//
// Brier score (Brier, 1950) is the proper scoring rule used here: the
// squared error between a predicted probability and the observed outcome
// (0 or 1). It is bounded in [0, 1] and has no undefined values — unlike
// the log score's -ln(0) at a certain-and-wrong forecast, which would make
// an occasional settlement unscoreable (or need a floor hack) for no
// benefit here, since both are proper scoring rules and the issue names
// either as acceptable (ADR-0022). Brier is also the rule gibson#284's
// aggregate already uses, so per-bet and aggregate values share one
// vocabulary rather than reporting two different statistics under the same
// name.

// brierScore is the squared error between a predicted probability and the
// observed binary outcome (ADR-0022): 0 for a perfectly confident and
// correct forecast, 1 for a perfectly confident and wrong one. It is the
// proper scoring rule for exactly one settled bet; the mean of many is
// gibson#284's TechniqueCalibration.BrierScore.
func brierScore(predicted, observed float64) float64 {
	diff := predicted - observed
	return diff * diff
}

// settlementOutcome maps a settlement verdict to the observed outcome a
// proper scoring rule scores against: 1.0 for a TRUE claim, 0.0 for FALSE.
// The scoring rule does not care which of the three settlement paths
// (predicate, exhaustion, HITL) reached the verdict, only what the verdict
// was.
func settlementOutcome(v SettlementVerdict) float64 {
	if v == SettlementVerdictTrue {
		return 1.0
	}
	return 0.0
}

// validPredictedProbability reports whether p is a usable probability. A
// settlement request whose declared staked confidence fails this check is
// refused before anything is scored or settled (bet_settlement.go).
func validPredictedProbability(p float64) bool {
	return p >= 0 && p <= 1
}
