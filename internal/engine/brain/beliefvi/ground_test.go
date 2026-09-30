// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefvi

import (
	"fmt"
	"reflect"
	"testing"
)

func TestGroundName_IsStableAndQualified(t *testing.T) {
	got, err := GroundName("host-a", "reachable")
	if err != nil {
		t.Fatal(err)
	}
	if got != "host-a::reachable" {
		t.Fatalf("got %q, want host-a::reachable", got)
	}
}

func TestGroundName_RejectsASeparatorInNodeOrVariableNames(t *testing.T) {
	if _, err := GroundName("host::a", "reachable"); err == nil {
		t.Fatal("expected an error for a separator in the node id")
	}
	if _, err := GroundName("host-a", "re::achable"); err == nil {
		t.Fatal("expected an error for a separator in the variable name")
	}
}

func TestSolveSlice_SingleRootNodeReturnsItsLeakAsThePosterior(t *testing.T) {
	nodes := []NodeSpec{{NodeID: "host-a", Variables: map[string]VariableSpec{"reachable": {Leak: 0.2}}}}
	out, err := SolveSlice(nodes, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	approxEqual(t, out["host-a"]["reachable"].True, 0.2, 1e-9, "leak-only posterior")
}

func TestSolveSlice_IntraNodeDependencyChainMatchesHandComputation(t *testing.T) {
	nodes := []NodeSpec{
		{
			NodeID: "host-a",
			Variables: map[string]VariableSpec{
				"reachable":   {Leak: 0.3},
				"exploitable": {DependsOn: map[string]float64{"reachable": 0.8}, Leak: 0.05},
				"juicy":       {DependsOn: map[string]float64{"exploitable": 0.9}, Leak: 0.0},
			},
		},
	}
	out, err := SolveSlice(nodes, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	pReachable := 0.3
	pExGivenRTrue := 1.0 - (1.0-0.05)*(1.0-0.8)
	pExGivenRFalse := 1.0 - (1.0 - 0.05)
	pExploitable := pReachable*pExGivenRTrue + (1-pReachable)*pExGivenRFalse

	pJuicyGivenExTrue := 1.0 - (1.0-0.0)*(1.0-0.9)
	pJuicyGivenExFalse := 1.0 - (1.0 - 0.0)
	pJuicy := pExploitable*pJuicyGivenExTrue + (1-pExploitable)*pJuicyGivenExFalse

	approxEqual(t, out["host-a"]["reachable"].True, pReachable, 1e-9, "reachable")
	approxEqual(t, out["host-a"]["exploitable"].True, pExploitable, 1e-9, "exploitable")
	approxEqual(t, out["host-a"]["juicy"].True, pJuicy, 1e-9, "juicy")
}

func TestSolveSlice_EnablementEdgeContributesAsAnAdditionalCause(t *testing.T) {
	nodes := []NodeSpec{
		{NodeID: "host-a", Variables: map[string]VariableSpec{"juicy": {Leak: 0.6}}},
		{NodeID: "host-b", Variables: map[string]VariableSpec{"reachable": {Leak: 0.1}}},
	}
	enablement := []EnablementCause{
		{SourceNode: "host-a", SourceVariable: "juicy", TargetNode: "host-b", TargetVariable: "reachable", Strength: 0.7},
	}
	out, err := SolveSlice(nodes, enablement, nil)
	if err != nil {
		t.Fatal(err)
	}

	pAJuicy := 0.6
	pBGivenATrue := 1.0 - (1.0-0.1)*(1.0-0.7)
	pBGivenAFalse := 1.0 - (1.0 - 0.1)
	wantBReachable := pAJuicy*pBGivenATrue + (1-pAJuicy)*pBGivenAFalse

	approxEqual(t, out["host-a"]["juicy"].True, pAJuicy, 1e-9, "host-a juicy")
	approxEqual(t, out["host-b"]["reachable"].True, wantBReachable, 1e-9, "host-b reachable")
	if !(out["host-b"]["reachable"].True > 0.1) {
		t.Errorf("enablement edge should have moved host-b's posterior off its bare leak")
	}
}

func TestGroundSlice_DenseFanInStaysTractable(t *testing.T) {
	n := 30
	nodes := make([]NodeSpec, 0, n+1)
	for i := range n {
		nodes = append(nodes, NodeSpec{NodeID: nodeName(i), Variables: map[string]VariableSpec{"juicy": {Leak: 0.4}}})
	}
	nodes = append(nodes, NodeSpec{NodeID: "target", Variables: map[string]VariableSpec{"reachable": {Leak: 0.05}}})

	enablement := make([]EnablementCause, 0, n)
	for i := range n {
		enablement = append(enablement, EnablementCause{
			SourceNode: nodeName(i), SourceVariable: "juicy",
			TargetNode: "target", TargetVariable: "reachable",
			Strength: 0.5,
		})
	}

	factors, err := GroundSlice(nodes, enablement)
	if err != nil {
		t.Fatal(err)
	}
	if len(factors) > 4*n+4 {
		t.Errorf("expected a bounded factor count, got %d for n=%d", len(factors), n)
	}
	for _, f := range factors {
		if len(f.Table) > 8 {
			t.Errorf("factor over %v has %d entries, want <= 8", f.Variables, len(f.Table))
		}
	}

	out, err := SolveSlice(nodes, enablement, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := out["target"]["reachable"].True
	if p < 0.0 || p > 1.0 {
		t.Errorf("posterior out of range: %v", p)
	}
	if !(p > 0.05) {
		t.Errorf("posterior should have moved off the bare leak: %v", p)
	}
}

func nodeName(i int) string {
	return fmt.Sprintf("up-%d", i)
}

func TestSolveSlice_EvidencePinsAVariableAndPropagates(t *testing.T) {
	nodes := []NodeSpec{
		{
			NodeID: "host-a",
			Variables: map[string]VariableSpec{
				"reachable":   {Leak: 0.3},
				"exploitable": {DependsOn: map[string]float64{"reachable": 0.9}, Leak: 0.0},
			},
		},
	}
	out, err := SolveSlice(nodes, nil, map[string]string{"host-a::reachable": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if out["host-a"]["reachable"].True != 1.0 {
		t.Fatalf("reachable = %v, want 1.0", out["host-a"]["reachable"].True)
	}
	approxEqual(t, out["host-a"]["exploitable"].True, 0.9, 1e-9, "exploitable | reachable=true")
}

func TestSolveSlice_DeterministicSameSliceSamePosteriors(t *testing.T) {
	build := func() ([]NodeSpec, []EnablementCause) {
		nodes := []NodeSpec{
			{NodeID: "host-a", Variables: map[string]VariableSpec{"juicy": {Leak: 0.55}}},
			{
				NodeID: "host-b",
				Variables: map[string]VariableSpec{
					"reachable":   {Leak: 0.1},
					"exploitable": {DependsOn: map[string]float64{"reachable": 0.8}, Leak: 0.02},
				},
			},
		}
		enablement := []EnablementCause{
			{SourceNode: "host-a", SourceVariable: "juicy", TargetNode: "host-b", TargetVariable: "reachable", Strength: 0.65},
		}
		return nodes, enablement
	}
	n1, e1 := build()
	n2, e2 := build()
	first, err := SolveSlice(n1, e1, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SolveSlice(n2, e2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("not deterministic: %+v vs %+v", first, second)
	}
}

func TestSolveSlice_NodeOrderDoesNotAffectTheResult(t *testing.T) {
	nodesForward := []NodeSpec{
		{NodeID: "host-a", Variables: map[string]VariableSpec{"juicy": {Leak: 0.5}}},
		{NodeID: "host-b", Variables: map[string]VariableSpec{"reachable": {Leak: 0.1}}},
	}
	nodesReversed := []NodeSpec{nodesForward[1], nodesForward[0]}
	enablement := []EnablementCause{
		{SourceNode: "host-a", SourceVariable: "juicy", TargetNode: "host-b", TargetVariable: "reachable", Strength: 0.4},
	}
	a, err := SolveSlice(nodesForward, enablement, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SolveSlice(nodesReversed, enablement, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("order-dependent: %+v vs %+v", a, b)
	}
}
