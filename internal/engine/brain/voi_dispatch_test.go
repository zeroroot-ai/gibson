// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// dispatchTestHierarchy mirrors taxonomy's own coverage_test.go fixture: two
// categories, two techniques rolling up to "prompt_injection", none rolling
// up to "data_exfiltration" — enough to exercise both a direct-technique
// match and a category-rollup match.
func dispatchTestHierarchy(t *testing.T) *taxonomy.TechniqueHierarchy {
	t.Helper()
	h, err := taxonomy.NewTechniqueHierarchy(
		[]taxonomy.CategoryID{"prompt_injection", "data_exfiltration"},
		map[taxonomy.TechniqueID]taxonomy.CategoryID{
			"direct_prompt_injection":   "prompt_injection",
			"indirect_prompt_injection": "prompt_injection",
		},
	)
	if err != nil {
		t.Fatalf("NewTechniqueHierarchy: %v", err)
	}
	return h
}

// dispatchCoverage builds a validated Coverage against h, failing the test on
// any construction error (every fixture id here is admitted by
// dispatchTestHierarchy, so a failure means the fixture itself is wrong).
func dispatchCoverage(t *testing.T, h *taxonomy.TechniqueHierarchy, categories []taxonomy.CategoryID, techniques []taxonomy.TechniqueID) taxonomy.Coverage {
	t.Helper()
	cov, err := taxonomy.NewCoverage(h, categories, techniques)
	if err != nil {
		t.Fatalf("NewCoverage: %v", err)
	}
	return cov
}

// TestCapabilitiesForTechnique_DirectTechniqueMatch proves a capability that
// declares the exact technique is returned, even when it declares no
// category coverage at all.
func TestCapabilitiesForTechnique_DirectTechniqueMatch(t *testing.T) {
	h := dispatchTestHierarchy(t)
	scanner := Capability{Kind: "tool", Name: "prompt-scanner",
		Coverage: dispatchCoverage(t, h, nil, []taxonomy.TechniqueID{"direct_prompt_injection"})}
	unrelated := Capability{Kind: "tool", Name: "port-scanner", Coverage: taxonomy.EmptyCoverage()}

	got := CapabilitiesForTechnique(h, "direct_prompt_injection", []Capability{scanner, unrelated})

	if len(got) != 1 || got[0].Name != "prompt-scanner" {
		t.Fatalf("CapabilitiesForTechnique = %+v, want only %q", got, "prompt-scanner")
	}
}

// TestCapabilitiesForTechnique_CategoryRollupMatch proves a candidate's
// technique reaches a capability that only declares the ROLLED-UP category,
// never the fine-grained technique itself — the taxonomy hierarchy is the
// bridge (ADR-0135), so this needs no separate table entry.
func TestCapabilitiesForTechnique_CategoryRollupMatch(t *testing.T) {
	h := dispatchTestHierarchy(t)
	generalist := Capability{Kind: "agent", Name: "injection-hunter",
		Coverage: dispatchCoverage(t, h, []taxonomy.CategoryID{"prompt_injection"}, nil)}

	got := CapabilitiesForTechnique(h, "indirect_prompt_injection", []Capability{generalist})

	if len(got) != 1 || got[0].Name != "injection-hunter" {
		t.Fatalf("CapabilitiesForTechnique = %+v, want only %q via category rollup", got, "injection-hunter")
	}
}

// TestCapabilitiesForTechnique_MatchesOnceEvenWithBothCoverages proves a
// capability declaring BOTH the technique and its category is still returned
// exactly once, not duplicated.
func TestCapabilitiesForTechnique_MatchesOnceEvenWithBothCoverages(t *testing.T) {
	h := dispatchTestHierarchy(t)
	belt := Capability{Kind: "agent", Name: "belt-and-suspenders", Coverage: dispatchCoverage(t, h,
		[]taxonomy.CategoryID{"prompt_injection"}, []taxonomy.TechniqueID{"direct_prompt_injection"})}

	got := CapabilitiesForTechnique(h, "direct_prompt_injection", []Capability{belt})

	if len(got) != 1 {
		t.Fatalf("CapabilitiesForTechnique = %+v, want exactly one match, not a duplicate", got)
	}
}

// TestCapabilitiesForTechnique_NoCoveringCapabilityIsExplicitEmpty proves the
// "no covering capability" case gibson#387 requires be handled explicitly:
// a technique nothing declares coverage for resolves to a nil/empty slice,
// never an error and never a panic.
func TestCapabilitiesForTechnique_NoCoveringCapabilityIsExplicitEmpty(t *testing.T) {
	h := dispatchTestHierarchy(t)
	unrelated := Capability{Kind: "tool", Name: "port-scanner", Coverage: taxonomy.EmptyCoverage()}

	got := CapabilitiesForTechnique(h, "direct_prompt_injection", []Capability{unrelated})

	if len(got) != 0 {
		t.Fatalf("CapabilitiesForTechnique = %+v, want none", got)
	}
}

// TestCapabilitiesForTechnique_EmptyTechniqueIsExplicitEmpty proves a
// candidate that names no technique at all (every VoICandidateEvidence, and a
// VoICandidateHypothesis with no Hypothesis.Technique set) resolves to no
// covering capabilities, even when the catalog is non-empty, and never
// panics.
func TestCapabilitiesForTechnique_EmptyTechniqueIsExplicitEmpty(t *testing.T) {
	h := dispatchTestHierarchy(t)
	scanner := Capability{Kind: "tool", Name: "prompt-scanner",
		Coverage: dispatchCoverage(t, h, nil, []taxonomy.TechniqueID{"direct_prompt_injection"})}

	got := CapabilitiesForTechnique(h, "", []Capability{scanner})

	if len(got) != 0 {
		t.Fatalf("CapabilitiesForTechnique(technique=\"\") = %+v, want none", got)
	}
}

// TestCapabilitiesForTechnique_NilHierarchyNeverPanics proves a nil hierarchy
// is handled explicitly (no covering capabilities), never a panic — the
// hierarchy is required to resolve the category rollup, so a caller that has
// none yet gets an honest empty answer rather than a crash.
func TestCapabilitiesForTechnique_NilHierarchyNeverPanics(t *testing.T) {
	scanner := Capability{Kind: "tool", Name: "prompt-scanner"}

	got := CapabilitiesForTechnique(nil, "direct_prompt_injection", []Capability{scanner})

	if len(got) != 0 {
		t.Fatalf("CapabilitiesForTechnique(hierarchy=nil) = %+v, want none", got)
	}
}

// TestCapabilitiesForTechnique_UnadmittedTechniqueStillMatchesDirectly proves
// a technique the hierarchy passed in does not itself admit (CategoryOf
// reports ok=false) can still match a capability that directly declares that
// same technique id — the category half of the match is unavailable, but the
// direct-technique half needs no hierarchy lookup of its own.
func TestCapabilitiesForTechnique_UnadmittedTechniqueStillMatchesDirectly(t *testing.T) {
	// A hierarchy that admits the technique (so a Coverage declaring it can be
	// constructed) but is queried through a DIFFERENT, narrower hierarchy that
	// does not roll it up to anything — CategoryOf must report ok=false on
	// that second hierarchy while the direct technique match still succeeds.
	full := dispatchTestHierarchy(t)
	scanner := Capability{Kind: "tool", Name: "prompt-scanner",
		Coverage: dispatchCoverage(t, full, nil, []taxonomy.TechniqueID{"direct_prompt_injection"})}

	narrow, err := taxonomy.NewTechniqueHierarchy([]taxonomy.CategoryID{"data_exfiltration"}, nil)
	if err != nil {
		t.Fatalf("NewTechniqueHierarchy: %v", err)
	}

	got := CapabilitiesForTechnique(narrow, "direct_prompt_injection", []Capability{scanner})

	if len(got) != 1 || got[0].Name != "prompt-scanner" {
		t.Fatalf("CapabilitiesForTechnique = %+v, want the direct match despite no category rollup", got)
	}
}

// TestCapabilitiesForTechnique_PreservesInputOrder proves matches come back
// in the order capabilities were given, not sorted or reordered — the
// resolution is a filter, not a ranking (ranking is VoI's own job, voi_plan.go).
func TestCapabilitiesForTechnique_PreservesInputOrder(t *testing.T) {
	h := dispatchTestHierarchy(t)
	first := Capability{Kind: "agent", Name: "zzz-agent",
		Coverage: dispatchCoverage(t, h, []taxonomy.CategoryID{"prompt_injection"}, nil)}
	second := Capability{Kind: "tool", Name: "aaa-tool",
		Coverage: dispatchCoverage(t, h, nil, []taxonomy.TechniqueID{"direct_prompt_injection"})}

	got := CapabilitiesForTechnique(h, "direct_prompt_injection", []Capability{first, second})

	if len(got) != 2 || got[0].Name != "zzz-agent" || got[1].Name != "aaa-tool" {
		t.Fatalf("CapabilitiesForTechnique = %+v, want input order preserved [zzz-agent, aaa-tool]", got)
	}
}
