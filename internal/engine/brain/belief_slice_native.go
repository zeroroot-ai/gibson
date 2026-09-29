// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// belief_slice_native.go is gibson#394 (ADR-0037): the real,
// beliefvi.GroundSlice/SolveSlice-backed SliceBeliefProvider that
// resolveSliceBeliefProvider's doc comment (internal/server/daemon) names as
// the missing piece — the ontology DATA a grounding step needs was not there
// yet. It now is: BeliefSchemaRegistry declares, per enablement-edge TYPE,
// the belief variable it feeds on its destination node
// (ontology.EnablementEdgeSpec.TargetVariable, ADR-0037 decision 1). What
// this file adds is turning that declaration into the beliefvi.NodeSpec /
// EnablementCause shape GroundSlice/SolveSlice already consume (landed by
// #401), so a bounded AttackGraph slice grounds to real noisy-OR causes
// instead of the deterministic placeholder.
//
// Strength is NEVER hand-authored here (ADR-0037 decisions 2-3): every cause
// this file builds — intra-node DependsOn and cross-node enablement alike —
// uses UninformativePriorStrength, the cold-start mean of an uninformative
// Beta prior. A learned per-edge-type Beta posterior (braintrain, #395) is a
// separate, later slice; when it lands, only the strength this file plugs
// into beliefvi.EnablementCause.Strength changes — the grounding structure
// (which variable is a cause of which) does not.

// UninformativePriorStrength is the cold-start noisy-OR strength (and leak)
// every cause grounds at until braintrain (#395) fits a per-edge-type Beta
// posterior from recorded outcomes (ADR-0037 decision 3): the mean of an
// uninformative Beta prior — Jeffreys Beta(1/2, 1/2) or uniform Beta(1, 1),
// both mean 1/2 — so belief still propagates from day one instead of waiting
// on data, and no hand-authored magic number stands in for a strength nobody
// has measured yet. #395 changes what feeds beliefvi.EnablementCause.Strength
// (a posterior mean instead of this constant); it does not change this
// constant's own meaning as the PRIOR that posterior starts from.
const UninformativePriorStrength = 0.5

// nativeSliceBeliefVersion identifies this provider's model: the schema
// structure ontology.BeliefSchemaRegistry declares, always grounded at the
// uninformative-prior cold start (ADR-0037 decisions 2-3) — never a learned
// posterior, which is #395's separate, later version.
const nativeSliceBeliefVersion = "native-slice-v0-uninformative-prior"

// nativeSliceBelief is the real SliceBeliefProvider (ADR-0029 §5/§6,
// ADR-0037): it grounds and exactly solves a bounded slice in-process via
// beliefvi, using registry to decide the noisy-OR structure (which variables
// exist, which depend on which, which enablement edges feed which target
// variable) and UninformativePriorStrength for every cause's strength.
type nativeSliceBelief struct {
	registry *ontology.BeliefSchemaRegistry
}

// NativeSliceBeliefProvider returns a SliceBeliefProvider that grounds every
// slice it is asked to score against registry's declared belief-PRM schema
// (ADR-0029 §2, §7; ADR-0037 decision 1), via beliefvi.GroundSlice/SolveSlice
// (#401). registry must not be nil.
func NativeSliceBeliefProvider(registry *ontology.BeliefSchemaRegistry) SliceBeliefProvider {
	return &nativeSliceBelief{registry: registry}
}

// ScoreSlice grounds slice against p.registry and returns every node's
// posterior, translated into the fixed Juicy/Exploitable/Reachable shape
// NodeBelief.Belief still carries (ADR-0029 §3's substrate has not yet
// generalized Belief itself beyond the Host seed's three named fields — a
// separate, later slice; this provider maps whichever of those three names a
// node's OWN declared variables include, and leaves the rest at their zero
// value, the same partial mapping placeholderSliceBelief's stand-in already
// accepted). On any grounding/solve error (e.g. a cyclic slice VE cannot
// factor) it returns an empty map — fail-quiet, no score rather than a wrong
// one, mirroring nativeBelief.Score's contract; the gate asks again on the
// next digest change.
func (p *nativeSliceBelief) ScoreSlice(slice AttackGraph) map[string]NodeBelief {
	nodes, causes := groundAttackGraph(slice, p.registry)

	posteriors, err := beliefvi.SolveSlice(nodes, causes, nil)
	if err != nil {
		return map[string]NodeBelief{}
	}

	out := make(map[string]NodeBelief, len(slice.Nodes))
	for _, n := range slice.Nodes {
		byVar := posteriors[n.ID]
		b := Belief{Model: nativeSliceBeliefVersion}
		if vb, ok := byVar["reachable"]; ok {
			b.Reachable = vb.True
		}
		if vb, ok := byVar["exploitable"]; ok {
			b.Exploitable = vb.True
		}
		if vb, ok := byVar["juicy"]; ok {
			b.Juicy = vb.True
		}
		out[n.ID] = NodeBelief{Belief: b}
	}
	return out
}

// Version reports the cold-start model identity (see nativeSliceBeliefVersion).
func (p *nativeSliceBelief) Version() string { return nativeSliceBeliefVersion }

// groundAttackGraph converts a derived AttackGraph (belief_attack_graph.go)
// into the beliefvi.NodeSpec/EnablementCause shape GroundSlice/SolveSlice
// consume:
//
//   - every node's own declared variables (AttackGraphNode.Variables) become
//     a beliefvi.NodeSpec, with each intra-node DependsOn parent contributing
//     UninformativePriorStrength as its noisy-OR cause strength, and the same
//     constant as the variable's leak — no per-parent number exists yet to
//     author or learn (ADR-0005/ADR-0037's shared "learned, not authored"
//     discipline), so the cold-start prior is the only defensible default.
//   - every kept enablement edge (graph.Edges, already ontology-filtered by
//     DeriveAttackGraph) becomes one beliefvi.EnablementCause per TERMINAL
//     variable of its source node's OWN intra-node dependency chain (see
//     terminalVariables) — "compromising the edge's From node"
//     (belief_attack_graph.go's doc comment) means the From node reaching
//     its own terminal belief state, not an arbitrarily-chosen one — feeding
//     whatever variable the registry declares that edge TYPE targets on its
//     destination node (ADR-0037 decision 1), at UninformativePriorStrength.
//
// An edge whose destination node does not itself declare the registry's
// declared target variable is skipped rather than erroring: a Domain Pack is
// free to flag an edge type as belief-propagating at a target variable that
// only some of its possible destination node types declare, and grounding
// must degrade gracefully rather than panicking on a slice that has not
// caught up. Likewise an edge type absent from the registry entirely (should
// not happen — DeriveAttackGraph already only keeps registry-flagged types —
// but this function does not assume its caller's invariant) is skipped.
func groundAttackGraph(graph AttackGraph, registry *ontology.BeliefSchemaRegistry) ([]beliefvi.NodeSpec, []beliefvi.EnablementCause) {
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
			for _, parent := range v.DependsOn {
				dependsOn[parent] = UninformativePriorStrength
			}
			vars[v.Name] = beliefvi.VariableSpec{DependsOn: dependsOn, Leak: UninformativePriorStrength}
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
		for _, sourceVar := range terminalVariables(registry, nodeKind[e.From]) {
			causes = append(causes, beliefvi.EnablementCause{
				SourceNode:     e.From,
				SourceVariable: sourceVar,
				TargetNode:     e.To,
				TargetVariable: targetVar,
				Strength:       UninformativePriorStrength,
			})
		}
	}

	return specs, causes
}

// terminalVariables returns the sorted, deterministic set of nodeKind's own
// declared belief variables that no OTHER variable of the same node type
// depends on (BeliefVariable.DependsOn) — the sink(s) of that node type's
// intra-node dependency chain. For Host's seed chain
// reachable -> exploitable -> juicy, the sole terminal is "juicy": nothing on
// Host depends on it, so it is Host's own final/most-compromised state.
//
// ADR-0037 adds only a TARGET-side declaration to the enablement-edge schema
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
