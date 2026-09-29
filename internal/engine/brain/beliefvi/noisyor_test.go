// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"fmt"
	"testing"
)

// bruteForceNoisyOrCPT is the textbook noisy-OR closed form, materialised as
// a full CPD table: P(variable=true | parents) = 1 - (1-leak) * prod_{i:
// parent_i=true} (1-strengths[i]) — the O(2**nParents) reference the
// decomposition must agree with. Mirrors test_noisy_or.py's
// _brute_force_cpt, including pgmpy's column order (last parent fastest).
func bruteForceNoisyOrCPT(t *testing.T, nParents int, strengths []float64, leak float64) (factor Factor, parents []string) {
	t.Helper()
	parents = make([]string, nParents)
	for i := range parents {
		parents[i] = fmt.Sprintf("p%d", i)
	}
	cols := 1 << nParents
	falseRow := make([]float64, cols)
	trueRow := make([]float64, cols)
	for col := range cols {
		prod := 1.0 - leak
		// Column bit i (0 = MSB = first parent .. last parent = LSB), matching
		// CPDToFactor's own flat convention (last parent varies fastest).
		for i := range nParents {
			bit := (col >> (nParents - 1 - i)) & 1
			if bit == 1 {
				prod *= 1.0 - strengths[i]
			}
		}
		pTrue := 1.0 - prod
		falseRow[col] = 1.0 - pTrue
		trueRow[col] = pTrue
	}
	cards := make([]int, nParents)
	for i := range cards {
		cards[i] = 2
	}
	f, err := CPDToFactor("y", [][]float64{falseRow, trueRow}, parents, cards)
	if err != nil {
		t.Fatalf("bruteForceNoisyOrCPT: %v", err)
	}
	return f, parents
}

func decomposedNoisyOr(t *testing.T, nParents int, strengths []float64, leak float64) (factors []Factor, parents []string) {
	t.Helper()
	parents = make([]string, nParents)
	causes := make([]NoisyOrCause, nParents)
	for i := range nParents {
		parents[i] = fmt.Sprintf("p%d", i)
		causes[i] = NoisyOrCause{Parent: parents[i], Strength: strengths[i]}
	}
	factors, err := NoisyOrFactors("y", causes, leak)
	if err != nil {
		t.Fatalf("NoisyOrFactors: %v", err)
	}
	return factors, parents
}

// withUniformParentPriors adds an independent Bernoulli(0.5) prior for every
// parent, so `y`'s marginal is well defined without conditioning on anything.
func withUniformParentPriors(t *testing.T, factors []Factor, parents []string) []Factor {
	t.Helper()
	out := append([]Factor(nil), factors...)
	for _, p := range parents {
		f, err := NewFactor([]string{p}, []float64{0.5, 0.5})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func TestNoisyOr_MatchesTheFullCPTMarginal(t *testing.T) {
	strengths := []float64{0.9, 0.2, 0.6, 0.05}
	leak := 0.1
	for n := range 5 {
		full, fullParents := bruteForceNoisyOrCPT(t, n, strengths[:n], leak)
		decomposed, decParents := decomposedNoisyOr(t, n, strengths[:n], leak)

		want, err := Query(withUniformParentPriors(t, []Factor{full}, fullParents), "y", map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := Query(withUniformParentPriors(t, decomposed, decParents), "y", map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		approxEqual(t, got["true"], want["true"], 1e-9, fmt.Sprintf("n=%d true", n))
		approxEqual(t, got["false"], want["false"], 1e-9, fmt.Sprintf("n=%d false", n))
	}
}

func TestNoisyOr_MatchesTheFullCPTConditionedOnParents(t *testing.T) {
	strengths := []float64{0.9, 0.2, 0.6, 0.05}
	leak := 0.15
	for n := 1; n <= 4; n++ {
		full, fullParents := bruteForceNoisyOrCPT(t, n, strengths[:n], leak)
		decomposed, decParents := decomposedNoisyOr(t, n, strengths[:n], leak)

		for assignment := range 1 << n {
			ev := make(map[string]string, n)
			ev2 := make(map[string]string, n)
			for i := range n {
				bit := (assignment >> (n - 1 - i)) & 1
				state := States[bit]
				ev[fullParents[i]] = state
				ev2[decParents[i]] = state
			}
			want, err := Query([]Factor{full}, "y", ev)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Query(decomposed, "y", ev2)
			if err != nil {
				t.Fatal(err)
			}
			approxEqual(t, got["true"], want["true"], 1e-9, fmt.Sprintf("n=%d assignment=%d", n, assignment))
		}
	}
}

func TestNoisyOr_ZeroCausesIsJustTheLeak(t *testing.T) {
	factors, err := NoisyOrFactors("y", nil, 0.37)
	if err != nil {
		t.Fatal(err)
	}
	if len(factors) != 1 {
		t.Fatalf("expected exactly one factor, got %d", len(factors))
	}
	got, err := Query(factors, "y", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	approxEqual(t, got["true"], 0.37, 1e-12, "leak-only")
}

func TestNoisyOr_FactorCountAndSizeStayLinearInCauses(t *testing.T) {
	n := 40
	causes := make([]NoisyOrCause, n)
	for i := range n {
		causes[i] = NoisyOrCause{Parent: fmt.Sprintf("p%d", i), Strength: 0.5}
	}
	factors, err := NoisyOrFactors("y", causes, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	if len(factors) > 2*n+1 {
		t.Errorf("expected O(n) factors, got %d for n=%d", len(factors), n)
	}
	for _, f := range factors {
		if len(f.Table) > 8 {
			t.Errorf("factor over %v has %d entries, want <= 8", f.Variables, len(f.Table))
		}
	}
}

func TestNoisyOr_DeterministicConstruction(t *testing.T) {
	causes := []NoisyOrCause{{Parent: "p0", Strength: 0.7}, {Parent: "p1", Strength: 0.3}}
	first, err := NoisyOrFactors("y", causes, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NoisyOrFactors("y", causes, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("factor count differs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if fmt.Sprint(first[i].Variables) != fmt.Sprint(second[i].Variables) {
			t.Errorf("variables differ at %d: %v vs %v", i, first[i].Variables, second[i].Variables)
		}
		for j := range first[i].Table {
			if first[i].Table[j] != second[i].Table[j] {
				t.Errorf("table differs at factor %d entry %d: %v vs %v", i, j, first[i].Table[j], second[i].Table[j])
			}
		}
	}
}

func TestNoisyOr_AuxiliaryVariablesDoNotCollideAcrossCalls(t *testing.T) {
	causes := []NoisyOrCause{{Parent: "p0", Strength: 0.5}, {Parent: "p1", Strength: 0.5}}
	a, err := NoisyOrFactors("host-a::exploitable", causes, 0.1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NoisyOrFactors("host-b::exploitable", causes, 0.1)
	if err != nil {
		t.Fatal(err)
	}
	aVars := map[string]struct{}{}
	for _, f := range a {
		for _, v := range f.Variables {
			if v != "p0" && v != "p1" {
				aVars[v] = struct{}{}
			}
		}
	}
	for _, f := range b {
		for _, v := range f.Variables {
			if v != "p0" && v != "p1" {
				if _, ok := aVars[v]; ok {
					t.Errorf("variable %q collides across calls", v)
				}
			}
		}
	}
}

func TestNoisyOr_OwnsTheTargetVariableExactlyOnce(t *testing.T) {
	causes := make([]NoisyOrCause, 5)
	for i := range causes {
		causes[i] = NoisyOrCause{Parent: fmt.Sprintf("p%d", i), Strength: 0.4}
	}
	factors, err := NoisyOrFactors("y", causes, 0.2)
	if err != nil {
		t.Fatal(err)
	}
	owners := 0
	for _, f := range factors {
		if f.Variables[0] == "y" {
			owners++
		}
	}
	if owners != 1 {
		t.Errorf("expected exactly one factor to own %q, got %d", "y", owners)
	}
}

func TestNoisyOr_CheckModelAcceptsTheDecomposition(t *testing.T) {
	causes := make([]NoisyOrCause, 6)
	for i := range causes {
		causes[i] = NoisyOrCause{Parent: fmt.Sprintf("p%d", i), Strength: 0.6}
	}
	factors, err := NoisyOrFactors("y", causes, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	all := append([]Factor(nil), factors...)
	variables := make([]string, 0, len(factors)+6)
	for _, f := range factors {
		variables = append(variables, f.Variables[0])
	}
	for i := range causes {
		p, err := NewFactor([]string{fmt.Sprintf("p%d", i)}, []float64{0.5, 0.5})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, p)
		variables = append(variables, p.Variables[0])
	}
	if err := CheckModel(all, variables); err != nil {
		t.Fatalf("CheckModel rejected the decomposition: %v", err)
	}
}
