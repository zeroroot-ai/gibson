// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "github.com/zeroroot-ai/gibson/internal/engine/taxonomy"

// voi_dispatch.go is VoI dispatch gating's technique -> capability bridge
// (ADR-0035 decision 4, gibson#387): it resolves a VoI candidate's technique
// to the capabilities that can address it, by rolling the technique up to its
// taxonomy category (TechniqueHierarchy.CategoryOf, gibson#379) and matching
// against every capability's declared Coverage (gibson#386). The rollup edge
// IS the bridge (ADR-0035 decision 2) — there is no separate reconciliation
// table between a candidate's fine-grained technique and a capability's
// coarse coverage declaration.
//
// This file makes the mapping resolvable; CapabilitiesForTechnique/
// capabilityRefs do not gate anything themselves. Ranking candidates by a deep
// multi-step plan is gibson#396's BAMCP planner (bamcp.go), built on this
// file. Turning "these capabilities cover this candidate" into an actual
// dispatch refusal is gibson#397's hard top-k enforcement — voiTopKCapabilities
// below, wired into DeciderWorker.decide via voiGatedDispatch (decider.go).

// CapabilitiesForTechnique resolves the capabilities in capabilities that can
// address technique: every capability whose declared Coverage includes
// technique itself, or the category technique rolls up to in hierarchy
// (TechniqueHierarchy.CategoryOf). Capabilities are returned in the order
// given, exactly once each, even when a capability's Coverage matches both
// the technique and its category.
//
// technique == "" (a candidate that names no technique — every
// VoICandidateEvidence, and a VoICandidateHypothesis whose source Hypothesis
// never had one set) and hierarchy == nil both resolve to a nil result:
// there is nothing to resolve against, a normal, expected shape, never an
// error and never a panic. A technique hierarchy does not admit
// (TechniqueHierarchy.CategoryOf reports ok=false) still gets a chance to
// match a capability directly by technique id — Coverage.HasTechnique needs
// no hierarchy lookup of its own — it only loses the category half of the
// match.
//
// A candidate whose technique matches no capability's coverage returns nil,
// the "no covering capability" case gibson#387 requires be handled
// explicitly: the caller decides what an uncovered candidate means (skip it,
// fall back to a default capability, refuse dispatch, ...), not this
// function.
func CapabilitiesForTechnique(hierarchy *taxonomy.TechniqueHierarchy, technique string, capabilities []Capability) []Capability {
	if technique == "" || hierarchy == nil {
		return nil
	}
	techniqueID := taxonomy.TechniqueID(technique)
	category, hasCategory := hierarchy.CategoryOf(techniqueID)

	var covering []Capability
	for _, capability := range capabilities {
		matchesTechnique := capability.Coverage.HasTechnique(techniqueID)
		matchesCategory := hasCategory && capability.Coverage.HasCategory(category)
		if matchesTechnique || matchesCategory {
			covering = append(covering, capability)
		}
	}
	return covering
}

// CapabilityRef identifies one dispatchable capability by the same (Kind,
// Name) pair DeciderDispatch/validateDispatch use to address it (decider.go)
// — a resolved dispatch TARGET, not a copy of the capability's full
// declaration. VoICandidate.CoveringCapabilities stores refs rather than full
// Capability values for a concrete reason, not stylistic preference:
// Capability.Coverage carries unexported internal state (taxonomy.Coverage's
// category/technique sets) that the JSON-based Timeline codec (ADR-0011,
// timeline_codec.go) silently drops on marshal — a persisted VoIPlanned event
// would replay with every covering capability's Coverage reset to empty. Kind
// and Name are plain exported strings, so a CapabilityRef replays exactly as
// recorded.
type CapabilityRef struct {
	Kind string
	Name string
}

// capabilityRefs projects capabilities down to their (Kind, Name) identity —
// see CapabilityRef's own doc comment for why VoICandidate.CoveringCapabilities
// stores refs and not full Capability values. Returns nil for an empty input,
// matching CapabilitiesForTechnique's own "no covering capability" shape.
func capabilityRefs(capabilities []Capability) []CapabilityRef {
	if len(capabilities) == 0 {
		return nil
	}
	refs := make([]CapabilityRef, len(capabilities))
	for i, c := range capabilities {
		refs[i] = CapabilityRef{Kind: c.Kind, Name: c.Name}
	}
	return refs
}

// voiTopKCapabilities flattens candidates' resolved CoveringCapabilities
// (each already the output of CapabilitiesForTechnique, via PlanVoI/BAMCPPlanner)
// into the set of (Kind, Name) dispatch targets gibson#397's hard top-k gate
// allows for this planning round — ADR-0026 decision 1: "the planner computes
// the top-k highest-value candidate moves; the LLM Decider picks from that set
// and cannot go outside it." candidates is expected to already be the
// planner's top-k (VoIPlanState.Candidates/VoIPlanned.Candidates — both are
// PlanVoI/BAMCPPlanner's topK-truncated output, never the unbounded set); this
// function does no truncation of its own.
//
// A candidate contributes nothing when its own CoveringCapabilities is nil —
// an evidence move (which never carries a technique, so voi_plan.go never
// resolves one) or a hypothesis the catalog does not cover. Being ranked in
// the top-k is necessary but not sufficient to license a dispatch: the
// candidate must also resolve to a concrete dispatchable capability, the same
// "no covering capability" case CapabilitiesForTechnique's own doc comment
// says the caller must decide — gibson#397 decides it here: no license, no
// dispatch. Returns nil (never a non-nil empty map) for an empty or
// all-uncovered candidates, so a caller can tell "no plan yet" and "a plan
// that covers nothing" apart from a genuinely empty allow-set the same way.
func voiTopKCapabilities(candidates []VoICandidate) map[CapabilityRef]bool {
	var allowed map[CapabilityRef]bool
	for _, c := range candidates {
		for _, ref := range c.CoveringCapabilities {
			if allowed == nil {
				allowed = make(map[CapabilityRef]bool, len(candidates))
			}
			allowed[ref] = true
		}
	}
	return allowed
}
