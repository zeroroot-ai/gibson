// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// chainGraph builds A -> B -> C -> D (each an enablement edge toward the
// next), all belief-bearing Host nodes, via the real DeriveAttackGraph
// (gibson#286) rather than a hand-built AttackGraph literal — so these tests
// exercise the actual boundary between the two slices.
func chainGraph(t *testing.T) AttackGraph {
	t.Helper()
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{
		{ID: "a", Kind: "Host"}, {ID: "b", Kind: "Host"},
		{ID: "c", Kind: "Host"}, {ID: "d", Kind: "Host"},
	}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "a", To: "b"},
		{Type: "RESOLVES_TO", From: "b", To: "c"},
		{Type: "RESOLVES_TO", From: "c", To: "d"},
	}
	return DeriveAttackGraph(nodes, edges, reg)
}

func nodeIDs(nodes []AttackGraphNode) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

// TestExtractBoundedSlice_ExpandsBackwardTowardTarget proves belief's
// dependency direction: a node's belief depends on what enables reaching it,
// so an unbounded slice toward D walks its full predecessor chain.
func TestExtractBoundedSlice_ExpandsBackwardTowardTarget(t *testing.T) {
	graph := chainGraph(t)

	got := ExtractBoundedSlice(graph, "d", SliceOptions{}, nil)

	want := []string{"a", "b", "c", "d"}
	if ids := nodeIDs(got.Nodes); !reflect.DeepEqual(ids, want) {
		t.Fatalf("Nodes = %v, want %v", ids, want)
	}
	wantEdges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "a", To: "b"},
		{Type: "RESOLVES_TO", From: "b", To: "c"},
		{Type: "RESOLVES_TO", From: "c", To: "d"},
	}
	if !reflect.DeepEqual(got.Edges, wantEdges) {
		t.Fatalf("Edges = %+v, want %+v", got.Edges, wantEdges)
	}
}

// TestExtractBoundedSlice_BoundedByMaxDepth is the depth half of the "depth +
// treewidth/node budget" acceptance criterion.
func TestExtractBoundedSlice_BoundedByMaxDepth(t *testing.T) {
	graph := chainGraph(t)

	tests := []struct {
		depth int
		want  []string
	}{
		{depth: 1, want: []string{"c", "d"}},
		{depth: 2, want: []string{"b", "c", "d"}},
		{depth: 3, want: []string{"a", "b", "c", "d"}},
		{depth: 100, want: []string{"a", "b", "c", "d"}}, // deeper than the chain: no further effect
	}
	for _, tc := range tests {
		got := ExtractBoundedSlice(graph, "d", SliceOptions{MaxDepth: tc.depth}, nil)
		if ids := nodeIDs(got.Nodes); !reflect.DeepEqual(ids, tc.want) {
			t.Errorf("MaxDepth=%d: Nodes = %v, want %v", tc.depth, ids, tc.want)
		}
	}
}

// TestExtractBoundedSlice_DenseGraphIsBounded is the issue's named
// acceptance criterion: a dense fan-in must not blow the node budget.
func TestExtractBoundedSlice_DenseGraphIsBounded(t *testing.T) {
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{{ID: "target", Kind: "Host"}}
	edges := []InfraEdge{}
	for i := range 20 {
		id := string(rune('a' + i))
		nodes = append(nodes, InfraNode{ID: id, Kind: "Host"})
		edges = append(edges, InfraEdge{Type: "RESOLVES_TO", From: id, To: "target"})
	}
	graph := DeriveAttackGraph(nodes, edges, reg)

	got := ExtractBoundedSlice(graph, "target", SliceOptions{NodeBudget: 5}, nil)

	if len(got.Nodes) > 5 {
		t.Fatalf("got %d nodes, want at most the 5-node budget", len(got.Nodes))
	}
	found := false
	for _, n := range got.Nodes {
		if n.ID == "target" {
			found = true
		}
	}
	if !found {
		t.Fatalf("target itself was pruned: %+v", got.Nodes)
	}
}

// TestExtractBoundedSlice_PrunesByRelevanceDeterministically is the
// relevance-pruning acceptance criterion: over budget, keep the target plus
// the most belief-relevant remaining nodes, ties broken by stable id.
func TestExtractBoundedSlice_PrunesByRelevanceDeterministically(t *testing.T) {
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{
		{ID: "target", Kind: "Host"},
		{ID: "p-high", Kind: "Host"},
		{ID: "p-mid", Kind: "Host"},
		{ID: "p-tie-a", Kind: "Host"},
		{ID: "p-tie-b", Kind: "Host"},
		{ID: "p-low", Kind: "Host"},
	}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "p-high", To: "target"},
		{Type: "RESOLVES_TO", From: "p-mid", To: "target"},
		{Type: "RESOLVES_TO", From: "p-tie-a", To: "target"},
		{Type: "RESOLVES_TO", From: "p-tie-b", To: "target"},
		{Type: "RESOLVES_TO", From: "p-low", To: "target"},
	}
	graph := DeriveAttackGraph(nodes, edges, reg)
	relevance := map[string]float64{
		"p-high":  0.9,
		"p-mid":   0.5,
		"p-tie-a": 0.2, // ties with p-tie-b; "p-tie-a" < "p-tie-b" wins the tiebreak
		"p-tie-b": 0.2,
		"p-low":   0.1,
	}

	// Budget for 3 total: target + the 2 most relevant predecessors.
	got := ExtractBoundedSlice(graph, "target", SliceOptions{NodeBudget: 3}, relevance)

	want := []string{"p-high", "p-mid", "target"} // sorted output order (see ExtractBoundedSlice doc)
	if ids := nodeIDs(got.Nodes); !reflect.DeepEqual(ids, want) {
		t.Fatalf("Nodes = %v, want %v", ids, want)
	}

	// Budget for 4: target + p-high + p-mid + the tiebreak winner (p-tie-a).
	got = ExtractBoundedSlice(graph, "target", SliceOptions{NodeBudget: 4}, relevance)
	want = []string{"p-high", "p-mid", "p-tie-a", "target"}
	if ids := nodeIDs(got.Nodes); !reflect.DeepEqual(ids, want) {
		t.Fatalf("Nodes = %v, want %v (deterministic id tiebreak between equally-relevant p-tie-a/p-tie-b)", ids, want)
	}
}

// TestExtractBoundedSlice_DeterministicAcrossInputOrder is the replay
// requirement: the same graph/target/opts/relevance always yields the same
// slice regardless of the order graph.Nodes/graph.Edges happen to be in.
func TestExtractBoundedSlice_DeterministicAcrossInputOrder(t *testing.T) {
	graph := chainGraph(t)
	reversed := AttackGraph{
		Nodes: append([]AttackGraphNode(nil), graph.Nodes...),
		Edges: append([]InfraEdge(nil), graph.Edges...),
	}
	for i, j := 0, len(reversed.Nodes)-1; i < j; i, j = i+1, j-1 {
		reversed.Nodes[i], reversed.Nodes[j] = reversed.Nodes[j], reversed.Nodes[i]
	}
	for i, j := 0, len(reversed.Edges)-1; i < j; i, j = i+1, j-1 {
		reversed.Edges[i], reversed.Edges[j] = reversed.Edges[j], reversed.Edges[i]
	}

	opts := SliceOptions{MaxDepth: 2, NodeBudget: 2}
	relevance := map[string]float64{"b": 0.5, "c": 0.9}

	want := ExtractBoundedSlice(graph, "d", opts, relevance)
	got := ExtractBoundedSlice(reversed, "d", opts, relevance)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order-dependent result:\n got  %+v\n want %+v", got, want)
	}
}

// TestExtractBoundedSlice_TargetNotInGraph degrades gracefully rather than
// panicking when asked to slice toward a node the graph does not have.
func TestExtractBoundedSlice_TargetNotInGraph(t *testing.T) {
	graph := chainGraph(t)
	got := ExtractBoundedSlice(graph, "does-not-exist", SliceOptions{}, nil)
	if len(got.Nodes) != 0 || len(got.Edges) != 0 {
		t.Fatalf("got %+v, want an empty AttackGraph", got)
	}
}

// TestExtractBoundedSlice_ResultStaysAcyclic slices a graph derived (via
// DeriveAttackGraph, gibson#286) from a CYCLIC infra fixture, and proves the
// slice inherits acyclicity from the already-acyclic input rather than
// needing its own cycle-breaking pass.
func TestExtractBoundedSlice_ResultStaysAcyclic(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	if err := ontology.RegisterCoreBeliefSchemaSeed(reg); err != nil {
		t.Fatalf("RegisterCoreBeliefSchemaSeed: %v", err)
	}
	nodes := []InfraNode{{ID: "host-a", Kind: "Host"}, {ID: "host-b", Kind: "Host"}, {ID: "host-c", Kind: "Host"}}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "host-a", To: "host-b"},
		{Type: "RESOLVES_TO", From: "host-b", To: "host-c"},
		{Type: "RESOLVES_TO", From: "host-c", To: "host-a"}, // closes a cycle in the raw infra graph
	}
	graph := DeriveAttackGraph(nodes, edges, reg)

	slice := ExtractBoundedSlice(graph, "host-c", SliceOptions{}, nil)
	if !isAcyclic(slice.Nodes, slice.Edges) {
		t.Fatalf("slice is cyclic: %+v", slice.Edges)
	}
}
