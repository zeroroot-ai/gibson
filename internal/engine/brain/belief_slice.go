// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "sort"

// belief_slice.go extracts the bounded, per-node slice belief is actually
// computed over (ADR-0029 §4-5, gibson#287): a target node's belief depends
// on what enables reaching it, never the whole graph, so inference runs on a
// bounded neighborhood "toward" the target rather than the full attack graph
// DeriveAttackGraph derives (gibson#286).
//
// The whole-graph DAG is already acyclic, and any subgraph of a DAG is itself
// acyclic — so, unlike DeriveAttackGraph, this file runs no cycle-breaking of
// its own. ADR-0029 §4's "a back-edge dropped in one node's slice is a
// forward edge in another's" describes cycle-breaking done per-slice directly
// against a cyclic infra graph; this codebase instead derives one global DAG
// once (gibson#286) and slices THAT, which is a strictly simpler, equally
// faithful reading the two issues' own blocking relationship states (#287 is
// "blocked by gibson#286 (the derived DAG to slice)" — its input is already a
// DAG, not the raw infra graph).

// SliceOptions bounds how far ExtractBoundedSlice expands from its target and
// how large the result may grow before relevance-based pruning kicks in
// (ADR-0029 §5). Both bounds are independent: MaxDepth is a hard cutoff on
// enablement-edge hops, evaluated first; NodeBudget then trims however many
// nodes MaxDepth left, by relevance. A non-positive value means "no bound on
// this dimension" (the sibling bound still applies) — the same convention
// ambient.go's AmbientProjection budget uses.
//
// NodeBudget is a node-count budget, the practical stand-in ADR-0029 §5 names
// alongside an actual treewidth bound: a literal tree-decomposition width
// bound needs its own (NP-hard in general) decomposition step, which nothing
// in this slice's acceptance criteria calls for — "the bound lives in the
// scope" (ADR-0029 §5), and a node count is a simple, sufficient scope bound.
type SliceOptions struct {
	MaxDepth   int
	NodeBudget int
}

// ExtractBoundedSlice extracts the bounded neighborhood "toward" target from
// graph: target's PREDECESSORS along graph's kept enablement edges, walked
// backward up to opts.MaxDepth hops (belief at a node depends on what enables
// reaching it, so the slice grows over ancestors, not descendants).
//
// If more nodes lie within MaxDepth than opts.NodeBudget allows, target is
// always kept, and the remaining budget goes to the most belief-relevant
// nodes: relevance[id] is the caller-supplied belief-relevance score
// (attention + surprise — attentionScore in attention.go, reused rather than
// redefined here; the caller decides how a given node kind's relevance is
// computed and passes the result in). An id relevance does not mention scores
// 0. Ties — including every id when relevance is nil — are broken by the
// smaller (lexicographically) stable node id, the same tiebreak
// DeriveAttackGraph (gibson#286) uses.
//
// graph must already be acyclic (DeriveAttackGraph's output). A subgraph of a
// DAG can never contain a cycle, so no cycle-breaking runs here — see the
// file doc comment. Returns an empty AttackGraph if target is not in graph.
//
// The same graph (any node/edge order), target, opts and relevance always
// produce the same slice: BFS distance does not depend on visit order, and
// the one ranking step (which nodes survive the budget) sorts on
// (relevance, id), a total order.
func ExtractBoundedSlice(graph AttackGraph, target string, opts SliceOptions, relevance map[string]float64) AttackGraph {
	byID := make(map[string]AttackGraphNode, len(graph.Nodes))
	for _, n := range graph.Nodes {
		byID[n.ID] = n
	}
	if _, ok := byID[target]; !ok {
		return AttackGraph{}
	}

	depth := sliceBackwardBFS(byID, graph.Edges, target, opts.MaxDepth)
	kept := sliceSelectByBudget(depth, target, opts.NodeBudget, relevance)
	return sliceBuildGraph(byID, graph.Edges, kept)
}

// sliceBackwardBFS walks graph.Edges backward from target — over
// PREDECESSORS, since a node's belief depends on what enables reaching it —
// bounded by maxDepth (<=0 means unbounded), and returns each visited id's
// distance in hops from target. BFS visits each id exactly once, so the
// result does not depend on edge or queue order.
func sliceBackwardBFS(byID map[string]AttackGraphNode, edges []InfraEdge, target string, maxDepth int) map[string]int {
	predecessors := make(map[string][]string, len(byID))
	for _, e := range edges {
		predecessors[e.To] = append(predecessors[e.To], e.From)
	}
	for to, froms := range predecessors {
		sort.Strings(froms)
		predecessors[to] = froms
	}

	depth := map[string]int{target: 0}
	queue := []string{target}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		d := depth[id]
		if maxDepth > 0 && d >= maxDepth {
			continue
		}
		for _, pred := range predecessors[id] {
			if _, known := byID[pred]; !known {
				continue // defensive: an edge into a node graph.Nodes does not list
			}
			if _, seen := depth[pred]; seen {
				continue
			}
			depth[pred] = d + 1
			queue = append(queue, pred)
		}
	}
	return depth
}

// sliceSelectByBudget returns the node ids ExtractBoundedSlice keeps: every
// id in depth (the BFS-bounded candidate set) when it fits within budget
// (<=0 means unbounded); otherwise target plus the (budget-1) most
// belief-relevant remaining ids, ranked by (relevance[id] descending, id
// ascending) — a total order, so the choice is deterministic even when every
// candidate ties on relevance.
func sliceSelectByBudget(depth map[string]int, target string, budget int, relevance map[string]float64) []string {
	candidates := make([]string, 0, len(depth))
	for id := range depth {
		candidates = append(candidates, id)
	}
	if budget <= 0 || len(candidates) <= budget {
		return candidates
	}

	rest := make([]string, 0, len(candidates)-1)
	for _, id := range candidates {
		if id != target {
			rest = append(rest, id)
		}
	}
	sort.Slice(rest, func(i, j int) bool {
		ri, rj := relevance[rest[i]], relevance[rest[j]]
		if ri != rj {
			return ri > rj // higher relevance first
		}
		return rest[i] < rest[j] // stable-id tiebreak
	})

	budgetForRest := max(min(budget-1, len(rest)), 0) // target always occupies one slot
	return append([]string{target}, rest[:budgetForRest]...)
}

// sliceBuildGraph materialises the kept node ids into an AttackGraph: nodes
// sorted by id, and every original edge whose endpoints both survived.
func sliceBuildGraph(byID map[string]AttackGraphNode, edges []InfraEdge, kept []string) AttackGraph {
	keptSet := make(map[string]struct{}, len(kept))
	for _, id := range kept {
		keptSet[id] = struct{}{}
	}

	sortedKept := append([]string(nil), kept...)
	sort.Strings(sortedKept)
	outNodes := make([]AttackGraphNode, 0, len(sortedKept))
	for _, id := range sortedKept {
		outNodes = append(outNodes, byID[id])
	}

	outEdges := make([]InfraEdge, 0)
	for _, e := range edges {
		_, fromOK := keptSet[e.From]
		_, toOK := keptSet[e.To]
		if fromOK && toOK {
			outEdges = append(outEdges, e)
		}
	}
	sortEdges(outEdges)

	return AttackGraph{Nodes: outNodes, Edges: outEdges}
}
