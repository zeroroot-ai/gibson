// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"math"
	"testing"
)

// simpleCPDs mirrors sidecar/belief/test_infer.py's SIMPLE fixture:
// P(reachable=true)=0.3, exploitable | reachable, juicy | exploitable — a
// clean analytic answer to check against.
func simpleFactors(t *testing.T) []Factor {
	t.Helper()
	reachable, err := CPDToFactor("reachable", [][]float64{{0.7}, {0.3}}, nil, nil)
	if err != nil {
		t.Fatalf("reachable: %v", err)
	}
	exploitable, err := CPDToFactor("exploitable", [][]float64{{0.9, 0.2}, {0.1, 0.8}}, []string{"reachable"}, []int{2})
	if err != nil {
		t.Fatalf("exploitable: %v", err)
	}
	juicy, err := CPDToFactor("juicy", [][]float64{{0.95, 0.4}, {0.05, 0.6}}, []string{"exploitable"}, []int{2})
	if err != nil {
		t.Fatalf("juicy: %v", err)
	}
	return []Factor{reachable, exploitable, juicy}
}

func approxEqual(t *testing.T, got, want, tol float64, msg string) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s: got %v, want %v (tol %v)", msg, got, want, tol)
	}
}

func TestQuery_MarginalMatchesHandComputation(t *testing.T) {
	// P(exploitable) = 0.7*0.1 + 0.3*0.8 = 0.31.
	got, err := Query(simpleFactors(t), "exploitable", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	approxEqual(t, got["true"], 0.31, 1e-12, "P(exploitable=true)")
	approxEqual(t, got["false"]+got["true"], 1.0, 1e-12, "sums to 1")
}

func TestQuery_ConditioningOnAParentReadsTheCPDColumnDirectly(t *testing.T) {
	got, err := Query(simpleFactors(t), "exploitable", map[string]string{"reachable": "true"})
	if err != nil {
		t.Fatal(err)
	}
	approxEqual(t, got["true"], 0.8, 1e-12, "P(exploitable=true|reachable=true)")
}

func TestQuery_ConditioningOnAChildRunsBayesBackwards(t *testing.T) {
	// P(reachable | exploitable=true) = 0.3*0.8 / 0.31.
	got, err := Query(simpleFactors(t), "reachable", map[string]string{"exploitable": "true"})
	if err != nil {
		t.Fatal(err)
	}
	approxEqual(t, got["true"], 0.24/0.31, 1e-12, "P(reachable=true|exploitable=true)")
}

func TestQuery_EvidenceOnTheQueryVariableIsIgnoredNotHonoured(t *testing.T) {
	free, err := Query(simpleFactors(t), "exploitable", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := Query(simpleFactors(t), "exploitable", map[string]string{"exploitable": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if free["true"] != pinned["true"] || free["false"] != pinned["false"] {
		t.Errorf("evidence on the query var changed the answer: free=%v pinned=%v", free, pinned)
	}
}

func TestQuery_EliminationOrderDoesNotChangeTheAnswer(t *testing.T) {
	factors := simpleFactors(t)
	baseline, err := Query(factors, "juicy", map[string]string{"reachable": "true"})
	if err != nil {
		t.Fatal(err)
	}
	for rotation := range factors {
		shuffled := append(append([]Factor(nil), factors[rotation:]...), factors[:rotation]...)
		got, err := Query(shuffled, "juicy", map[string]string{"reachable": "true"})
		if err != nil {
			t.Fatal(err)
		}
		approxEqual(t, got["true"], baseline["true"], 1e-12, "rotation")
	}
}

func TestQuery_RepeatedQueriesAreBitIdentical(t *testing.T) {
	factors := simpleFactors(t)
	first, err := Query(factors, "juicy", map[string]string{"reachable": "true"})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		got, err := Query(factors, "juicy", map[string]string{"reachable": "true"})
		if err != nil {
			t.Fatal(err)
		}
		if got["true"] != first["true"] || got["false"] != first["false"] {
			t.Errorf("not bit-identical: got %v, want %v", got, first)
		}
	}
}

func TestQuery_ImpossibleEvidenceRaisesRatherThanNormalisingNoise(t *testing.T) {
	reachable, _ := CPDToFactor("reachable", [][]float64{{1.0}, {0.0}}, nil, nil)
	exploitable, _ := CPDToFactor("exploitable", [][]float64{{0.9, 0.2}, {0.1, 0.8}}, []string{"reachable"}, []int{2})
	juicy, _ := CPDToFactor("juicy", [][]float64{{0.5}, {0.5}}, nil, nil)
	_, err := Query([]Factor{reachable, exploitable, juicy}, "exploitable", map[string]string{"reachable": "true"})
	if err == nil {
		t.Fatal("expected a zero-probability error")
	}
}

func TestCheckModel_RejectsAnUnnormalisedCPD(t *testing.T) {
	f, _ := CPDToFactor("juicy", [][]float64{{0.5}, {0.7}}, nil, nil)
	if err := CheckModel([]Factor{f}, []string{"juicy"}); err == nil {
		t.Fatal("expected an unnormalised-cpd error")
	}
}

func TestCheckModel_RejectsAMissingCPD(t *testing.T) {
	f, _ := CPDToFactor("juicy", [][]float64{{0.5}, {0.5}}, nil, nil)
	if err := CheckModel([]Factor{f}, []string{"juicy", "reachable"}); err == nil {
		t.Fatal("expected a missing-cpd error")
	}
}

func TestCheckModel_RejectsAnUndeclaredParent(t *testing.T) {
	f, _ := CPDToFactor("juicy", [][]float64{{0.5, 0.5}, {0.5, 0.5}}, []string{"ghost"}, []int{2})
	if err := CheckModel([]Factor{f}, []string{"juicy"}); err == nil {
		t.Fatal("expected an undeclared-parent error")
	}
}

func TestCheckModel_RejectsACycle(t *testing.T) {
	juicy, _ := CPDToFactor("juicy", [][]float64{{0.5, 0.5}, {0.5, 0.5}}, []string{"exploitable"}, []int{2})
	exploitable, _ := CPDToFactor("exploitable", [][]float64{{0.5, 0.5}, {0.5, 0.5}}, []string{"juicy"}, []int{2})
	if err := CheckModel([]Factor{juicy, exploitable}, []string{"juicy", "exploitable"}); err == nil {
		t.Fatal("expected a cyclic-model error")
	}
}

func TestCPDToFactor_RejectsATableOfTheWrongShape(t *testing.T) {
	_, err := CPDToFactor("juicy", [][]float64{{0.5, 0.5}, {0.5, 0.5}}, []string{"a", "b"}, []int{2, 2})
	if err == nil {
		t.Fatal("expected a shape error")
	}
}
