// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"math"
	"testing"
)

// findings_test.go proves the finding-derived noisy-OR parents of exploitable
// (gibson#478) against the shipped base-v1 artifact, with the exact noisy-OR
// closed form — not just monotonicity.
//
// Every one of exploitable's six parents (reachable, svc_ssh, svc_https,
// finding_critical, finding_high, exploit_demonstrated) is observed in these
// cases, so exploitable's marginal collapses to a single CPD column: the exact
// value P(exploitable=true) = 1 - (1-base) * prod over active new causes of
// (1 - strength). base here is P(exploitable | reachable,ssh,https all true) =
// 0.80 in the artifact; the strengths are 0.90 (critical), 0.60 (high) and
// 0.98 (demonstrated).
func exploitableModel(t *testing.T) *BeliefModel {
	t.Helper()
	art, err := DefaultArtifact()
	if err != nil {
		t.Fatalf("default artifact: %v", err)
	}
	m, err := NewBeliefModel(art)
	if err != nil {
		t.Fatalf("build model: %v", err)
	}
	return m
}

// allParentsObserved returns evidence that observes every parent of exploitable,
// toggling the three new causes, so the scored exploitable is one exact column.
func allParentsObserved(fc, fh, ed bool) Evidence {
	return Evidence{
		OpenPorts:           []int{22, 443},
		Services:            []string{"22/ssh", "443/https"},
		Reachable:           true,
		FindingCritical:     fc,
		FindingHigh:         fh,
		ExploitDemonstrated: ed,
	}
}

func scoreExploitable(t *testing.T, m *BeliefModel, ev Evidence) float64 {
	t.Helper()
	r, err := m.Score(ev, nil)
	if err != nil {
		t.Fatalf("score: %v", err)
	}
	return r.Exploitable
}

func closeTo(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

const exploitableBaseAllTrue = 0.80 // P(exploitable | reachable,ssh,https)

// TestExploitable_NoFindingEvidenceIsBaseline proves the parity property at the
// model level: with all three new causes false, exploitable is exactly the
// pre-gibson#478 base value — a false noisy-OR cause contributes nothing.
func TestExploitable_NoFindingEvidenceIsBaseline(t *testing.T) {
	m := exploitableModel(t)
	got := scoreExploitable(t, m, allParentsObserved(false, false, false))
	if !closeTo(got, exploitableBaseAllTrue) {
		t.Fatalf("baseline exploitable = %v, want %v", got, exploitableBaseAllTrue)
	}
}

// TestExploitable_FindingCriticalNoisyOr proves finding_critical raises
// exploitable by exactly its noisy-OR strength (0.90).
func TestExploitable_FindingCriticalNoisyOr(t *testing.T) {
	m := exploitableModel(t)
	got := scoreExploitable(t, m, allParentsObserved(true, false, false))
	want := 1 - (1-exploitableBaseAllTrue)*(1-0.90) // = 0.98
	if !closeTo(got, want) {
		t.Fatalf("finding_critical exploitable = %v, want %v", got, want)
	}
	if !(got > exploitableBaseAllTrue) {
		t.Fatalf("finding_critical must raise exploitable above baseline %v, got %v", exploitableBaseAllTrue, got)
	}
}

// TestExploitable_FindingHighNoisyOr proves finding_high raises exploitable by
// exactly its noisy-OR strength (0.60), below critical.
func TestExploitable_FindingHighNoisyOr(t *testing.T) {
	m := exploitableModel(t)
	got := scoreExploitable(t, m, allParentsObserved(false, true, false))
	want := 1 - (1-exploitableBaseAllTrue)*(1-0.60) // = 0.92
	if !closeTo(got, want) {
		t.Fatalf("finding_high exploitable = %v, want %v", got, want)
	}
}

// TestExploitable_DemonstratedIsStrongest proves a demonstrated exploit raises
// exploitable by exactly its noisy-OR strength (0.98) — the strongest cause,
// above a critical finding.
func TestExploitable_DemonstratedIsStrongest(t *testing.T) {
	m := exploitableModel(t)
	got := scoreExploitable(t, m, allParentsObserved(false, false, true))
	want := 1 - (1-exploitableBaseAllTrue)*(1-0.98) // = 0.996
	if !closeTo(got, want) {
		t.Fatalf("exploit_demonstrated exploitable = %v, want %v", got, want)
	}

	critical := scoreExploitable(t, m, allParentsObserved(true, false, false))
	high := scoreExploitable(t, m, allParentsObserved(false, true, false))
	if !(got > critical && critical > high) {
		t.Fatalf("strength order must be demonstrated(%v) > critical(%v) > high(%v)", got, critical, high)
	}
}

// TestExploitable_CausesCombine proves two active causes combine multiplicatively
// (independent noisy-OR), stronger than either alone.
func TestExploitable_CausesCombine(t *testing.T) {
	m := exploitableModel(t)
	got := scoreExploitable(t, m, allParentsObserved(true, false, true))
	want := 1 - (1-exploitableBaseAllTrue)*(1-0.90)*(1-0.98) // = 0.9996
	if !closeTo(got, want) {
		t.Fatalf("critical+demonstrated exploitable = %v, want %v", got, want)
	}
}
