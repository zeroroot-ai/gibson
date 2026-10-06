// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// belief_slice_native.go is gibson#394 (ADR-0137): the real,
// beliefvi.GroundSlice/SolveSlice-backed SliceBeliefProvider that
// resolveSliceBeliefProvider's doc comment (internal/server/daemon) names as
// the missing piece — the ontology DATA a grounding step needs was not there
// yet. It now is: BeliefSchemaRegistry declares, per enablement-edge TYPE,
// the belief variable it feeds on its destination node
// (ontology.EnablementEdgeSpec.TargetVariable, ADR-0137). What
// this file adds is turning that declaration into the beliefvi.NodeSpec /
// EnablementCause shape GroundSlice/SolveSlice already consume (landed by
// #401), so a bounded AttackGraph slice grounds to real noisy-OR causes
// instead of the deterministic placeholder.
//
// Strength is NEVER hand-authored here (ADR-0137). Each strength grounds at
// UninformativePriorStrength until a fitted artifact is pinned: when
// NativeSliceBeliefProvider is given a non-nil
// PinnedEdgeStrengthPosteriorProvider (braintrain.EdgePosteriorProvider, fit
// offline by the belief trainer), groundAttackGraph reads the posterior MEAN
// of each enablement edge type (gibson#395), of each intra-node DependsOn
// strength and of each leak (gibson#720) instead. The grounding STRUCTURE
// (which variable is a cause of which) never changes, only the strength
// numbers.

// UninformativePriorStrength is the cold-start noisy-OR strength (and leak)
// every intra-node cause grounds at, and every enablement-edge cause grounds
// at when no posterior is pinned (ADR-0137): the mean of an
// uninformative Beta prior — Jeffreys Beta(1/2, 1/2) or uniform Beta(1, 1),
// both mean 1/2 — so belief still propagates from day one instead of waiting
// on data, and no hand-authored magic number stands in for a strength nobody
// has measured yet. It is also the fallback groundAttackGraph and BAMCP both
// still use for an edge TYPE a pinned posterior has no fitted row for
// (bamcp.go's UninformativeEdgePosteriors returns this same mean).
const UninformativePriorStrength = 0.5

// nativeSliceBeliefVersion identifies this provider's grounding SCHEME: the
// schema structure ontology.BeliefSchemaRegistry declares and the
// uninformative-prior cold start (ADR-0137). It never changes
// when a posterior is pinned — see (*nativeSliceBelief).version, which
// appends the pinned posterior's own artifact version alongside it, so a
// scored Belief.Model always names BOTH "which grounding scheme" and "which
// edge-posterior artifact, if any" that produced it.
const nativeSliceBeliefVersion = "native-slice-v0-uninformative-prior"

// nativeSliceBelief is the real SliceBeliefProvider (ADR-0129,
// ADR-0137): it grounds and exactly solves a bounded slice in-process via
// beliefvi, using registry to decide the noisy-OR structure (which variables
// exist, which depend on which, which enablement edges feed which target
// variable). Every cause grounds at UninformativePriorStrength unless
// posteriors is non-nil, in which case an enablement-edge cause's strength is
// that edge type's fitted Beta posterior MEAN (gibson#395, ADR-0137's
// "one output, two uses" — BAMCP Thompson-samples the same posterior).
type nativeSliceBelief struct {
	registry   *ontology.BeliefSchemaRegistry
	posteriors PinnedEdgeStrengthPosteriorProvider
}

// NativeSliceBeliefProvider returns a SliceBeliefProvider that grounds every
// slice it is asked to score against registry's declared belief-PRM schema
// (ADR-0129; ADR-0137), via beliefvi.GroundSlice/SolveSlice
// (#401). registry must not be nil. posteriors is the per-edge-type Beta
// posterior a mission pins for replay (gibson#395); nil preserves the
// original cold-start-only behavior (every enablement edge grounds at
// UninformativePriorStrength) exactly.
func NativeSliceBeliefProvider(registry *ontology.BeliefSchemaRegistry, posteriors PinnedEdgeStrengthPosteriorProvider) SliceBeliefProvider {
	return &nativeSliceBelief{registry: registry, posteriors: posteriors}
}

// ScoreSlice grounds slice against p.registry (and p.posteriors, if pinned)
// and returns every node's posterior, translated into the fixed
// Juicy/Exploitable/Reachable shape NodeBelief.Belief still carries
// (ADR-0129's substrate has not yet generalized Belief itself beyond the
// Host seed's three named fields — a separate, later slice; this provider
// maps whichever of those three names a node's OWN declared variables
// include, and leaves the rest at their zero value). On any grounding/solve
// error (e.g. a cyclic slice VE cannot factor) it returns an empty map —
// fail-quiet, no score rather than a wrong one, mirroring
// nativeBelief.Score's contract; the gate asks again on the next digest
// change.
//
// Every scored node's Belief.Model is stamped with p.version() — the SAME
// value Version() reports — so the Timeline event this feeds (SliceScored,
// belief_slice_gate.go) is a durable, replayable RECORD of which edge-posterior
// artifact (if any) produced it (ADR-0134's discipline, gibson#395's
// mission-pin requirement: replay re-folds the recorded event, it never
// re-selects or re-loads a posterior file).
func (p *nativeSliceBelief) ScoreSlice(slice AttackGraph) map[string]NodeBelief {
	nodes, causes := groundAttackGraph(slice, p.registry, p.posteriors)

	posteriors, err := beliefvi.SolveSlice(nodes, causes, nil)
	if err != nil {
		return map[string]NodeBelief{}
	}

	version := p.version()
	out := make(map[string]NodeBelief, len(slice.Nodes))
	for _, n := range slice.Nodes {
		byVar := posteriors[n.ID]
		b := Belief{Model: version}
		if vb, ok := byVar["reachable"]; ok {
			b.Reachable = vb.True
		}
		if vb, ok := byVar["exploitable"]; ok {
			b.Exploitable = vb.True
		}
		if vb, ok := byVar["juicy"]; ok {
			b.Juicy = vb.True
		}
		out[n.ID] = NodeBelief{Belief: b, CauseEdgeTypes: sliceCauseEdgeTypes(slice, n.ID)}
	}
	return out
}

// Version reports p.version() (see its doc comment).
func (p *nativeSliceBelief) Version() string { return p.version() }

// version is nativeSliceBeliefVersion (the grounding scheme, unchanged by
// ADR-0137) alone when no posterior is pinned, or that plus the
// pinned posterior artifact's own Version() when one is (gibson#395). This is
// the "mission-pinned for replay" identity: whatever this returns at score
// time is exactly what lands in the recorded Belief.Model, so a later replay
// reads back which artifact produced it without re-selecting anything.
func (p *nativeSliceBelief) version() string {
	if p.posteriors == nil {
		return nativeSliceBeliefVersion
	}
	return nativeSliceBeliefVersion + "+edges:" + p.posteriors.Version()
}

// groundAttackGraph converts a derived AttackGraph (belief_attack_graph.go)
// into the beliefvi.NodeSpec/EnablementCause shape GroundSlice/SolveSlice
// consume:
//
//   - every node's own declared variables (AttackGraphNode.Variables) become
//     a beliefvi.NodeSpec. Each intra-node DependsOn parent contributes the
//     posterior MEAN of its fitted in-node strength as its noisy-OR cause
//     strength, and the variable's leak is the posterior MEAN of its fitted
//     leak (gibson#720). With no pinned posteriors both are
//     UninformativePriorStrength, and a pinned artifact with no fitted value
//     falls back to the same Beta(1,1) mean.
//   - every kept enablement edge (graph.Edges, already ontology-filtered by
//     DeriveAttackGraph) becomes one beliefvi.EnablementCause per TERMINAL
//     variable of its source node's OWN intra-node dependency chain (see
//     terminalVariables) — "compromising the edge's From node"
//     (belief_attack_graph.go's doc comment) means the From node reaching
//     its own terminal belief state, not an arbitrarily-chosen one — feeding
//     whatever variable the registry declares that edge TYPE targets on its
//     destination node (ADR-0137), at that edge type's fitted Beta
//     posterior MEAN when posteriors is non-nil (gibson#395), or
//     UninformativePriorStrength when it is nil or has no fitted row for that
//     type — posteriors.Posterior always returns SOMETHING (a fitted provider
//     falls back to the same uninformative Beta(1,1) internally, mirroring
//     bamcp.go's UninformativeEdgePosteriors), so "nil provider" is the only
//     branch this function itself needs.
//
// An edge whose destination node does not itself declare the registry's
// declared target variable is skipped rather than erroring: a Domain Pack is
// free to flag an edge type as belief-propagating at a target variable that
// only some of its possible destination node types declare, and grounding
// must degrade gracefully rather than panicking on a slice that has not
// caught up. Likewise an edge type absent from the registry entirely (should
// not happen — DeriveAttackGraph already only keeps registry-flagged types —
// but this function does not assume its caller's invariant) is skipped.
func groundAttackGraph(graph AttackGraph, registry *ontology.BeliefSchemaRegistry, posteriors PinnedEdgeStrengthPosteriorProvider) ([]beliefvi.NodeSpec, []beliefvi.EnablementCause) {
	nodeVariables := make(map[string]map[string]struct{}, len(graph.Nodes))
	nodeKind := make(map[string]string, len(graph.Nodes))
	specs := make([]beliefvi.NodeSpec, 0, len(graph.Nodes))

	for _, n := range graph.Nodes {
		names := make(map[string]struct{}, len(n.Variables))
		for _, v := range n.Variables {
			names[v.Name] = struct{}{}
		}
		nodeVariables[n.ID] = names
		nodeKind[n.ID] = n.Kind

		vars := make(map[string]beliefvi.VariableSpec, len(n.Variables))
		for _, v := range n.Variables {
			dependsOn := make(map[string]float64, len(v.DependsOn))
			leak := UninformativePriorStrength
			if posteriors != nil {
				leak = posteriors.Leak(n.Kind, v.Name).Mean()
			}
			for _, parent := range v.DependsOn {
				dependsOn[parent] = UninformativePriorStrength
				if posteriors != nil {
					dependsOn[parent] = posteriors.InNodeStrength(n.Kind, v.Name, parent).Mean()
				}
			}
			vars[v.Name] = beliefvi.VariableSpec{DependsOn: dependsOn, Leak: leak}
		}
		specs = append(specs, beliefvi.NodeSpec{NodeID: n.ID, Variables: vars})
	}

	var causes []beliefvi.EnablementCause
	for _, e := range graph.Edges {
		targetVar, ok := registry.EnablementEdgeTargetVariable(e.Type)
		if !ok {
			continue
		}
		if _, declared := nodeVariables[e.To][targetVar]; !declared {
			continue
		}
		strength := enablementEdgeStrength(e.Type, posteriors)
		for _, sourceVar := range terminalVariables(registry, nodeKind[e.From]) {
			causes = append(causes, beliefvi.EnablementCause{
				SourceNode:     e.From,
				SourceVariable: sourceVar,
				TargetNode:     e.To,
				TargetVariable: targetVar,
				Strength:       strength,
			})
		}
	}

	return specs, causes
}

// enablementEdgeStrength resolves one enablement-edge TYPE's noisy-OR
// strength: UninformativePriorStrength when posteriors is nil (no posterior
// pinned, ADR-0137's cold start), else that edge type's fitted
// Beta posterior MEAN (gibson#395, ADR-0137 — the other of "one
// output, two uses" is bamcp.go Thompson-sampling the same posterior). A
// pinned provider with no fitted row for edgeType still returns a
// posterior — braintrain.EdgePosteriorProvider falls back to
// UninformativeEdgePosteriors internally, so its Mean() is exactly
// UninformativePriorStrength too; this function never needs to special-case
// "known type" vs "unknown type" itself.
func enablementEdgeStrength(edgeType string, posteriors EdgeStrengthPosteriorProvider) float64 {
	if posteriors == nil {
		return UninformativePriorStrength
	}
	return posteriors.Posterior(edgeType).Mean()
}

// terminalVariables returns the sorted, deterministic set of nodeKind's own
// declared belief variables that no OTHER variable of the same node type
// depends on (BeliefVariable.DependsOn) — the sink(s) of that node type's
// intra-node dependency chain. For Host's seed chain
// reachable -> exploitable -> juicy, the sole terminal is "juicy": nothing on
// Host depends on it, so it is Host's own final/most-compromised state.
//
// ADR-0137 adds only a TARGET-side declaration to the enablement-edge schema
// (decision 1) — it deliberately does not add a second, source-side field,
// so grounding derives the cross-node CAUSE side structurally instead:
// belief_attack_graph.go's doc comment describes an enablement edge as
// "compromising the edge's From node enables reaching/exploiting its To
// node", which this reads as the From node reaching ITS OWN terminal belief
// state — not an arbitrarily-chosen one, and not a second number to author.
// A node type with more than one terminal variable (an intra-node DAG with
// more than one sink) contributes one independent noisy-OR cause per
// terminal; noisy-OR already combines independent causes, so multiple sinks
// need no tie-break.
func terminalVariables(registry *ontology.BeliefSchemaRegistry, nodeKind string) []string {
	vars := registry.Variables(nodeKind)
	dependedOn := make(map[string]struct{}, len(vars))
	for _, v := range vars {
		for _, dep := range v.DependsOn {
			dependedOn[dep] = struct{}{}
		}
	}
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		if _, ok := dependedOn[v.Name]; !ok {
			out = append(out, v.Name)
		}
	}
	sort.Strings(out)
	return out
}
