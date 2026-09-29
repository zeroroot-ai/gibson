// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// testBeliefRegistry builds a small BeliefSchemaRegistry for these tests: Host
// and Finding are belief-bearing, RESOLVES_TO and AFFECTS are enablement
// edges, HAS_PORT is not (mirrors the real seed's shape without depending on
// its exact content, except where a test explicitly wants the real seed).
func testBeliefRegistry(t *testing.T) *ontology.BeliefSchemaRegistry {
	t.Helper()
	reg := ontology.NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("test", ontology.BeliefSchemaExtension{
		Nodes: []ontology.NodeBeliefSchema{
			{NodeType: "Host", Variables: []ontology.BeliefVariable{{Name: "reachable"}}},
			{NodeType: "Finding", Variables: []ontology.BeliefVariable{{Name: "verified"}}},
		},
		EnablementEdges: []ontology.EnablementEdgeSpec{
			{RelType: "RESOLVES_TO", TargetVariable: "reachable"},
			{RelType: "AFFECTS", TargetVariable: "verified"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterExtension: %v", err)
	}
	return reg
}

// isAcyclic is a generic, algorithm-independent check: no path in edges may
// revisit a node. It is the acceptance-criteria assertion itself ("the result
// is acyclic"), kept deliberately decoupled from DeriveAttackGraph's own
// potential-based bookkeeping so a bug in that bookkeeping cannot also hide
// from this check.
func isAcyclic(nodes []AttackGraphNode, edges []InfraEdge) bool {
	adj := make(map[string][]string, len(nodes))
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	const (
		unvisited = 0
		inStack   = 1
		done      = 2
	)
	state := make(map[string]int, len(nodes))
	var dfs func(id string) bool
	dfs = func(id string) bool {
		state[id] = inStack
		for _, next := range adj[id] {
			if state[next] == inStack {
				return false
			}
			if state[next] == unvisited && !dfs(next) {
				return false
			}
		}
		state[id] = done
		return true
	}
	for _, n := range nodes {
		if state[n.ID] == unvisited {
			if !dfs(n.ID) {
				return false
			}
		}
	}
	return true
}

// TestDeriveAttackGraph_DirectsOnlyDeclaredEnablementEdges is the first
// acceptance criterion: an edge is part of the attack graph only when the
// ontology flags its relationship type as belief-propagating (ADR-0029 §7);
// every other edge type is left out entirely — not even reported as dropped,
// since "dropped" means "cut to break a cycle" (see the next test), not
// "never eligible in the first place".
func TestDeriveAttackGraph_DirectsOnlyDeclaredEnablementEdges(t *testing.T) {
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{{ID: "host-a", Kind: "Host"}, {ID: "host-b", Kind: "Host"}}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "host-a", To: "host-b"}, // enablement: kept
		{Type: "HAS_PORT", From: "host-a", To: "host-b"},    // not enablement: excluded
	}

	got := DeriveAttackGraph(nodes, edges, reg)

	if len(got.Edges) != 1 || got.Edges[0] != (InfraEdge{Type: "RESOLVES_TO", From: "host-a", To: "host-b"}) {
		t.Fatalf("Edges = %+v, want exactly the RESOLVES_TO edge", got.Edges)
	}
	if len(got.Dropped) != 0 {
		t.Fatalf("Dropped = %+v, want none — HAS_PORT was never eligible, not cut", got.Dropped)
	}
}

// TestDeriveAttackGraph_ExcludesNonBeliefBearingNodes proves a node with no
// declared belief schema cannot appear in the derived graph, and an
// enablement-typed edge touching one is excluded along with it — a node with
// no belief variables has nothing for the graph to propagate.
func TestDeriveAttackGraph_ExcludesNonBeliefBearingNodes(t *testing.T) {
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{{ID: "host-a", Kind: "Host"}, {ID: "port-1", Kind: "Port"}} // Port is not belief-bearing
	edges := []InfraEdge{{Type: "RESOLVES_TO", From: "host-a", To: "port-1"}}

	got := DeriveAttackGraph(nodes, edges, reg)

	if len(got.Nodes) != 1 || got.Nodes[0].ID != "host-a" {
		t.Fatalf("Nodes = %+v, want only host-a", got.Nodes)
	}
	if len(got.Edges) != 0 || len(got.Dropped) != 0 {
		t.Fatalf("Edges=%+v Dropped=%+v, want both empty: the edge touches an excluded node", got.Edges, got.Dropped)
	}
}

// TestDeriveAttackGraph_BreaksCyclesDeterministically is the cyclic-infra
// fixture the issue's acceptance criteria call for: a 3-cycle over Hosts, all
// linked by the same enablement edge type, must yield a stable, acyclic
// graph — the exact edge cut, not just "some" edge, since replay requires the
// SAME cut every time (ADR-0029 §1/§4: topological potential, tiebroken by
// stable id).
func TestDeriveAttackGraph_BreaksCyclesDeterministically(t *testing.T) {
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{{ID: "host-a", Kind: "Host"}, {ID: "host-b", Kind: "Host"}, {ID: "host-c", Kind: "Host"}}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "host-a", To: "host-b"},
		{Type: "RESOLVES_TO", From: "host-b", To: "host-c"},
		{Type: "RESOLVES_TO", From: "host-c", To: "host-a"}, // closes the cycle
	}

	got := DeriveAttackGraph(nodes, edges, reg)

	if !isAcyclic(got.Nodes, got.Edges) {
		t.Fatalf("DeriveAttackGraph produced a cyclic graph: edges=%+v", got.Edges)
	}
	if len(got.Edges) != 2 || len(got.Dropped) != 1 {
		t.Fatalf("Edges=%+v Dropped=%+v, want exactly 2 kept and 1 dropped", got.Edges, got.Dropped)
	}
	// host-a sorts first, so it is the first ready node (in-degree 0 once we
	// also consider it's the smallest of the cycle when nothing is ready) —
	// the deterministic tiebreak names it as the forced pick, which makes the
	// edge INTO it (host-c -> host-a) the one that gets cut.
	wantDropped := InfraEdge{Type: "RESOLVES_TO", From: "host-c", To: "host-a"}
	if got.Dropped[0] != wantDropped {
		t.Fatalf("Dropped[0] = %+v, want %+v (the deterministic cut for this fixture)", got.Dropped[0], wantDropped)
	}
	wantEdges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "host-a", To: "host-b"},
		{Type: "RESOLVES_TO", From: "host-b", To: "host-c"},
	}
	if !reflect.DeepEqual(got.Edges, wantEdges) {
		t.Fatalf("Edges = %+v, want %+v", got.Edges, wantEdges)
	}
}

// TestDeriveAttackGraph_DeterministicAcrossInputOrder is the replay
// requirement: the same infra state must yield the same DAG regardless of
// the order the caller happens to hand nodes/edges in (a graph query gives no
// order guarantee at all). Runs the same cyclic fixture through several
// random shuffles and requires byte-for-byte identical results.
func TestDeriveAttackGraph_DeterministicAcrossInputOrder(t *testing.T) {
	reg := testBeliefRegistry(t)
	baseNodes := []InfraNode{
		{ID: "host-a", Kind: "Host"}, {ID: "host-b", Kind: "Host"},
		{ID: "host-c", Kind: "Host"}, {ID: "host-d", Kind: "Host"},
	}
	baseEdges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "host-a", To: "host-b"},
		{Type: "RESOLVES_TO", From: "host-b", To: "host-c"},
		{Type: "RESOLVES_TO", From: "host-c", To: "host-a"},
		{Type: "RESOLVES_TO", From: "host-a", To: "host-d"},
		{Type: "AFFECTS", From: "host-d", To: "host-b"},
	}

	want := DeriveAttackGraph(append([]InfraNode(nil), baseNodes...), append([]InfraEdge(nil), baseEdges...), reg)

	//nolint:gosec // G404: shuffling a fixed test fixture deterministically (seeded), not a security context.
	rnd := rand.New(rand.NewSource(1))
	for i := range 5 {
		nodes := append([]InfraNode(nil), baseNodes...)
		edges := append([]InfraEdge(nil), baseEdges...)
		rnd.Shuffle(len(nodes), func(i, j int) { nodes[i], nodes[j] = nodes[j], nodes[i] })
		rnd.Shuffle(len(edges), func(i, j int) { edges[i], edges[j] = edges[j], edges[i] })

		got := DeriveAttackGraph(nodes, edges, reg)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d: DeriveAttackGraph is order-dependent:\n got  %+v\n want %+v", i, got, want)
		}
	}
}

// TestDeriveAttackGraph_NodeCarriesDeclaredVariables proves each retained
// node's Variables come straight from the ontology's schema (registry.Variables),
// so a later grounding step has what it needs without a second registry lookup.
func TestDeriveAttackGraph_NodeCarriesDeclaredVariables(t *testing.T) {
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{{ID: "host-a", Kind: "Host"}}

	got := DeriveAttackGraph(nodes, nil, reg)

	if len(got.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(got.Nodes))
	}
	want := reg.Variables("Host")
	sortVars := func(vs []ontology.BeliefVariable) {
		sort.Slice(vs, func(i, j int) bool { return vs[i].Name < vs[j].Name })
	}
	gotVars := got.Nodes[0].Variables
	sortVars(want)
	sortVars(gotVars)
	if !reflect.DeepEqual(gotVars, want) {
		t.Fatalf("Variables = %+v, want %+v", gotVars, want)
	}
}

// TestDeriveAttackGraph_ConsumesCoreSeedRegistry proves this package wires
// against Lane D's real, shipped registry (gibson#296) — not just a
// hand-rolled test double — using NewBeliefSchemaRegistry and
// RegisterCoreBeliefSchemaSeed exactly as the belief engine will.
func TestDeriveAttackGraph_ConsumesCoreSeedRegistry(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	if err := ontology.RegisterCoreBeliefSchemaSeed(reg); err != nil {
		t.Fatalf("RegisterCoreBeliefSchemaSeed: %v", err)
	}

	nodes := []InfraNode{{ID: "host-a", Kind: "Host"}, {ID: "host-b", Kind: "Host"}}
	edges := []InfraEdge{{Type: "RESOLVES_TO", From: "host-a", To: "host-b"}}

	got := DeriveAttackGraph(nodes, edges, reg)

	if len(got.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (both Host, the seed's belief-bearing kind)", len(got.Nodes))
	}
	if len(got.Edges) != 1 || got.Edges[0].Type != "RESOLVES_TO" {
		t.Fatalf("Edges = %+v, want the RESOLVES_TO edge (a seeded enablement type)", got.Edges)
	}
	// The seed's three-variable funnel (ADR-0005) travels with the node.
	names := make([]string, 0, len(got.Nodes[0].Variables))
	for _, v := range got.Nodes[0].Variables {
		names = append(names, v.Name)
	}
	sort.Strings(names)
	wantNames := []string{"exploitable", "juicy", "reachable"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("Variables = %v, want %v", names, wantNames)
	}
}

// TestDeriveAttackGraph_EmptyInput proves the zero-node/zero-edge case
// degrades to an empty graph rather than panicking.
func TestDeriveAttackGraph_EmptyInput(t *testing.T) {
	got := DeriveAttackGraph(nil, nil, testBeliefRegistry(t))
	if len(got.Nodes) != 0 || len(got.Edges) != 0 || len(got.Dropped) != 0 {
		t.Fatalf("got %+v, want an entirely empty AttackGraph", got)
	}
}
