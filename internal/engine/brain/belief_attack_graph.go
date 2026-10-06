// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// belief_attack_graph.go derives the directed-acyclic Bayesian attack graph
// belief propagates over (ADR-0129) from the raw infra graph — whatever
// cyclic shape trust/reachability/credential relationships actually take.
//
// It answers ADR-0129's two questions structurally:
//
//  1. Direction: an edge is part of the attack graph only when the ontology's
//     schema (internal/engine/ontology, gibson#296) flags its relationship
//     type as belief-propagating — compromising the edge's From node enables
//     reaching/exploiting its To node. Direction is taken verbatim from the
//     infra graph; this package never re-derives it from anything else.
//  2. Acyclicity: the raw graph is not acyclic in general (a credential loop,
//     a DNS resolution cycle), so cycles are broken deterministically by a
//     topological potential — an ordinal assigned by a cycle-breaking
//     topological sort, ties AND forced picks both resolved by the
//     lexicographically smallest stable node id (ADR-0129). An edge
//     whose potential does not strictly increase From -> To is the back-edge
//     that closed the cycle, and is cut.
//
// Out of scope here (later, separate slices): grounding the per-node CPTs
// into a solvable network and running inference (gibson#275's belief engine
// proper), and the BOUNDED, per-node SLICE extraction ADR-0129-5 describes
// for the actual inference hot path — this derivation produces one whole-graph
// DAG from whatever infra graph it is handed; slicing it down before inference
// is a different concern with a different, bounded-by-budget algorithm.

// InfraNode is one node from the infra graph, as this derivation sees it: its
// taxonomy node type (Kind, e.g. "Host") and a stable id (ID) unique across
// the WHOLE infra graph the caller hands in — not just within Kind. Callers
// already have one (a graph merge key, a brain entity id stringified with its
// kind, ...); this package treats ID as an opaque, comparable string it never
// interprets beyond the ordering ADR-0129's tiebreak requires.
type InfraNode struct {
	ID   string
	Kind string
}

// InfraEdge is one directed relationship from the infra graph, as observed:
// a relationship type plus its two endpoints (by InfraNode.ID). Direction is
// however the caller's graph records it — DeriveAttackGraph takes it as the
// enablement direction verbatim for every type the ontology flags as
// belief-propagating; it does not re-derive direction from anything else.
type InfraEdge struct {
	Type string
	From string // an InfraNode.ID
	To   string // an InfraNode.ID
}

// AttackGraphNode is one node retained in the derived attack graph: a
// belief-bearing infra node (ontology.BeliefSchemaRegistry.IsBeliefBearing),
// its declared belief variables (ontology.BeliefSchemaRegistry.Variables,
// ADR-0129 — carried here so a later grounding step needs no second
// registry lookup), and Potential: the topological potential
// DeriveAttackGraph assigned it (ADR-0129). Potential is a deterministic
// ordinal, not a literal attack-distance hop count: every kept edge goes from
// a strictly smaller Potential to a strictly larger one, by construction.
type AttackGraphNode struct {
	InfraNode
	Variables []ontology.BeliefVariable
	Potential int
}

// AttackGraph is an enablement graph belief propagates over (ADR-0129) —
// never the raw infra graph. After BreakCycles, Edges is the kept, directed,
// acyclic edge set, and Dropped is every enablement edge cut to break a cycle:
// a back-edge in THAT graph. A back-edge of the whole graph can be a forward
// edge in one bounded slice, so the belief engine slices the uncut
// EnablementGraph and breaks the cycles of each slice (gibson#700).
type AttackGraph struct {
	Nodes   []AttackGraphNode
	Edges   []InfraEdge
	Dropped []InfraEdge
}

// DeriveAttackGraph builds the Bayesian attack graph from the raw infra
// graph (ADR-0129):
//
//  1. Keep only nodes the ontology declares belief-bearing (registry.IsBeliefBearing)
//     — a node with no belief variables cannot be part of a graph belief
//     propagates over.
//  2. Keep only edges whose type the ontology flags as belief-propagating
//     (registry.EnablementEdgeTypes) AND whose two endpoints both survived
//     step 1. Every other edge is excluded outright — never reported in
//     Dropped, which is reserved for a cycle's back-edge (step 4).
//  3. Assign every surviving node a topological potential by a deterministic
//     cycle-breaking topological sort (Kahn's algorithm): repeatedly take the
//     lexicographically smallest node id with no remaining incoming kept
//     edge; once no such node exists — meaning what is left is entirely
//     cyclic — take the lexicographically smallest remaining node id
//     instead, forcing it through. That forced pick is exactly ADR-0129's
//     "topological potential, tiebroken by stable id": the same total order
//     (potential, then id) resolves both an ordinary tie among ready nodes
//     and a genuine cycle.
//  4. Drop every kept edge whose potential does not strictly increase from
//     From to To. That is precisely the set of edges a cycle forced out of
//     order — cutting them is what makes the result acyclic.
//
// The same infra state (same nodes, same edges, in any input order) always
// produces the same AttackGraph: node membership and edge eligibility depend
// only on set membership, and the sort's only two choices (which ready node
// to take, which node to force) are both resolved by the same total order
// (node id, ascending) — so replay reproduces the derivation exactly.
//
// registry must not be nil.
func DeriveAttackGraph(nodes []InfraNode, edges []InfraEdge, registry *ontology.BeliefSchemaRegistry) AttackGraph {
	return BreakCycles(EnablementGraph(nodes, edges, registry))
}

// EnablementGraph runs steps 1 and 2 of DeriveAttackGraph: it keeps the
// belief-bearing nodes and the enablement edges between them, and cuts
// nothing. The result can hold a cycle. The belief engine slices this graph
// and breaks the cycles of each slice (ADR-0129, gibson#700): an edge that a
// cut of the whole graph removes can be a forward edge inside one slice.
// Each node has Potential 0 until BreakCycles assigns one.
//
// registry must not be nil.
func EnablementGraph(nodes []InfraNode, edges []InfraEdge, registry *ontology.BeliefSchemaRegistry) AttackGraph {
	beliefBearing := make(map[string]InfraNode, len(nodes))
	for _, n := range nodes {
		if registry.IsBeliefBearing(n.Kind) {
			beliefBearing[n.ID] = n
		}
	}

	enablementTypes := registry.EnablementEdgeTypes()
	enablement := make(map[string]struct{}, len(enablementTypes))
	for _, t := range enablementTypes {
		enablement[t] = struct{}{}
	}

	kept := make([]InfraEdge, 0, len(edges))
	for _, e := range edges {
		if _, ok := enablement[e.Type]; !ok {
			continue
		}
		if _, ok := beliefBearing[e.From]; !ok {
			continue
		}
		if _, ok := beliefBearing[e.To]; !ok {
			continue
		}
		kept = append(kept, e)
	}
	sortEdges(kept)

	ids := make([]string, 0, len(beliefBearing))
	for id := range beliefBearing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	outNodes := make([]AttackGraphNode, 0, len(ids))
	for _, id := range ids {
		n := beliefBearing[id]
		outNodes = append(outNodes, AttackGraphNode{InfraNode: n, Variables: registry.Variables(n.Kind)})
	}
	return AttackGraph{Nodes: outNodes, Edges: kept}
}

// BreakCycles runs steps 3 and 4 of DeriveAttackGraph on g: it assigns each
// node a topological potential and moves each edge whose potential does not
// strictly increase into Dropped. The result is acyclic. Edges that g already
// listed in Dropped stay there. The same g in any order gives the same result.
func BreakCycles(g AttackGraph) AttackGraph {
	ids := make([]string, 0, len(g.Nodes))
	byID := make(map[string]AttackGraphNode, len(g.Nodes))
	for _, n := range g.Nodes {
		ids = append(ids, n.ID)
		byID[n.ID] = n
	}
	sort.Strings(ids)

	potential := assignTopologicalPotential(ids, g.Edges)

	dagEdges := make([]InfraEdge, 0, len(g.Edges))
	dropped := append([]InfraEdge(nil), g.Dropped...)
	for _, e := range g.Edges {
		if potential[e.From] < potential[e.To] {
			dagEdges = append(dagEdges, e)
		} else {
			dropped = append(dropped, e)
		}
	}
	sortEdges(dagEdges)
	sortEdges(dropped)

	outNodes := make([]AttackGraphNode, 0, len(ids))
	for _, id := range ids {
		n := byID[id]
		n.Potential = potential[id]
		outNodes = append(outNodes, n)
	}
	return AttackGraph{Nodes: outNodes, Edges: dagEdges, Dropped: dropped}
}

// sortEdges puts edges in a fixed, input-order-independent sequence (by From,
// then To, then Type) so DeriveAttackGraph's output never depends on the
// order the caller happened to hand its edges in — only on which edges are
// present, matching the determinism DeriveAttackGraph documents.
func sortEdges(edges []InfraEdge) {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Type < edges[j].Type
	})
}

// assignTopologicalPotential runs the deterministic cycle-breaking
// topological sort described on DeriveAttackGraph and returns each id's
// assigned rank. ids must be sorted ascending and unique; every edge's From
// and To must be members of ids (DeriveAttackGraph guarantees both).
//
// Complexity is O(len(ids)^2 + len(edges)): each of len(ids) iterations scans
// ids once to find the next node to process. Belief inference itself runs on
// depth/budget-bounded slices (ADR-0129), not the whole graph, so this
// whole-graph derivation is not expected to run on a scale where that matters;
// a heap-based O((V+E) log V) version is a mechanical change if it ever does.
func assignTopologicalPotential(ids []string, edges []InfraEdge) map[string]int {
	inDegree := make(map[string]int, len(ids))
	out := make(map[string][]string, len(ids))
	for _, id := range ids {
		inDegree[id] = 0
	}
	for _, e := range edges {
		inDegree[e.To]++
		out[e.From] = append(out[e.From], e.To)
	}
	// Deterministic neighbour order, so relaxing in-degree below never depends
	// on the caller's edge-slice order.
	for from, tos := range out {
		sort.Strings(tos)
		out[from] = tos
	}

	processed := make(map[string]bool, len(ids))
	potential := make(map[string]int, len(ids))
	next := 0

	for len(processed) < len(ids) {
		pick := ""
		// Prefer the smallest id with no remaining incoming kept edge — the
		// ordinary topological-sort step.
		for _, id := range ids {
			if !processed[id] && inDegree[id] == 0 {
				pick = id
				break
			}
		}
		if pick == "" {
			// Nothing is ready: every remaining node has an incoming edge from
			// another remaining node — a cycle. Force the smallest remaining
			// id, the deterministic tiebreak ADR-0129 names. Whichever
			// of its incoming edges is still unaccounted-for becomes the
			// back-edge DeriveAttackGraph drops once potentials are compared.
			for _, id := range ids {
				if !processed[id] {
					pick = id
					break
				}
			}
		}

		processed[pick] = true
		potential[pick] = next
		next++
		for _, to := range out[pick] {
			if !processed[to] {
				inDegree[to]--
			}
		}
	}

	return potential
}
