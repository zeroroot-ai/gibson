// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// TestBrierScore covers the scoring math directly (gibson#277's "unit tests
// over the scoring math" acceptance criterion): 0 for a perfectly confident
// and correct forecast, 1 for a perfectly confident and wrong one, and the
// familiar 0.25 "maximally uncertain" value at predicted=0.5 regardless of
// the outcome.
func TestBrierScore(t *testing.T) {
	tests := []struct {
		name                string
		predicted, observed float64
		want                float64
	}{
		{name: "perfectly confident and correct (true)", predicted: 1.0, observed: 1.0, want: 0.0},
		{name: "perfectly confident and correct (false)", predicted: 0.0, observed: 0.0, want: 0.0},
		{name: "perfectly confident and wrong (predicted true, was false)", predicted: 1.0, observed: 0.0, want: 1.0},
		{name: "perfectly confident and wrong (predicted false, was true)", predicted: 0.0, observed: 1.0, want: 1.0},
		{name: "maximally uncertain, turned out true", predicted: 0.5, observed: 1.0, want: 0.25},
		{name: "maximally uncertain, turned out false", predicted: 0.5, observed: 0.0, want: 0.25},
		{name: "overconfident and wrong", predicted: 0.9, observed: 0.0, want: 0.81},
		{name: "underconfident but right", predicted: 0.1, observed: 1.0, want: 0.81},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := brierScore(tc.predicted, tc.observed); !floatsEqual(got, tc.want) {
				t.Fatalf("brierScore(%v, %v) = %v, want %v", tc.predicted, tc.observed, got, tc.want)
			}
		})
	}
}

// TestSettlementOutcome proves the observed-outcome mapping used to score
// against: TRUE is 1.0, FALSE is 0.0, regardless of which of the three
// settlement paths (predicate, exhaustion, HITL) produced the verdict.
func TestSettlementOutcome(t *testing.T) {
	if got := settlementOutcome(SettlementVerdictTrue); got != 1.0 {
		t.Fatalf("settlementOutcome(true) = %v, want 1.0", got)
	}
	if got := settlementOutcome(SettlementVerdictFalse); got != 0.0 {
		t.Fatalf("settlementOutcome(false) = %v, want 0.0", got)
	}
}

// TestValidPredictedProbability proves the range gate a settlement request's
// staked confidence must pass before it can be scored.
func TestValidPredictedProbability(t *testing.T) {
	tests := []struct {
		p    float64
		want bool
	}{
		{p: -0.01, want: false},
		{p: 0, want: true},
		{p: 0.5, want: true},
		{p: 1, want: true},
		{p: 1.01, want: false},
	}
	for _, tc := range tests {
		if got := validPredictedProbability(tc.p); got != tc.want {
			t.Fatalf("validPredictedProbability(%v) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

// floatsEqual compares floats computed by simple, exact arithmetic (squaring
// a difference of values representable exactly in binary floating point in
// every test case above), so a tight epsilon is just defensive, not a
// concession to real floating-point error.
func floatsEqual(a, b float64) bool {
	const epsilon = 1e-9
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < epsilon
}
