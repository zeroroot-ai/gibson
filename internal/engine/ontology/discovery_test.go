// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// -----------------------------------------------------------------------
// Acceptance: an agent can propose an ontology extension as a structural
// hypothesis (gibson#274, acceptance criterion 1).
// -----------------------------------------------------------------------

func TestProposeExtension_AcceptsValidHierarchy(t *testing.T) {
	r := NewReasoner(NewMetrics())

	h := StructuralHypothesis{
		Proposer: "agent-run-1",
		Claim:    "iis hosts should subclass web-server",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:IIS", SubClassOf: "tech:WebServer"},
			},
		},
	}

	out := ProposeExtension(r, h)

	require.True(t, out.Accepted)
	require.NoError(t, out.Rejected)
	require.NotEmpty(t, out.ExtensionName)
	assert.Contains(t, r.Ancestors("tech:IIS"), "tech:WebServer")
}

// -----------------------------------------------------------------------
// Acceptance: cycles/unknown prefixes are rejected as today (criterion 3).
// -----------------------------------------------------------------------

func TestProposeExtension_RejectsCycle(t *testing.T) {
	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("core", sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{"tech": "https://example.com/tech#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			{NodeType: "technology", Label: "tech:A", SubClassOf: "tech:B"},
		},
	}))

	h := StructuralHypothesis{
		Proposer: "agent-run-2",
		Claim:    "B is also a subclass of A",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:B", SubClassOf: "tech:A"},
			},
		},
	}

	out := ProposeExtension(r, h)

	require.False(t, out.Accepted)
	require.Error(t, out.Rejected)
	var cycleErr *CycleError
	require.ErrorAs(t, out.Rejected, &cycleErr)
	// Rejected proposal must not have applied: no descendant relationship.
	assert.NotContains(t, r.Ancestors("tech:B"), "tech:A")
}

func TestProposeExtension_RejectsUnknownPrefix(t *testing.T) {
	r := NewReasoner(NewMetrics())

	h := StructuralHypothesis{
		Proposer: "agent-run-3",
		Claim:    "propose a class with an undeclared prefix",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "unknownpfx:Thing"},
			},
		},
	}

	out := ProposeExtension(r, h)

	require.False(t, out.Accepted)
	require.Error(t, out.Rejected)
	var prefixErr *UnknownPrefixError
	require.ErrorAs(t, out.Rejected, &prefixErr)
	assert.Empty(t, r.Ancestors("unknownpfx:Thing"))
}

// -----------------------------------------------------------------------
// Attribution is required: an unattributed or textless proposal is not a
// hypothesis another agent could pick up and test (mirrors
// brain.applyHypothesisObserved's "a claim with no text records nothing").
// -----------------------------------------------------------------------

func TestProposeExtension_RejectsEmptyProposer(t *testing.T) {
	r := NewReasoner(NewMetrics())
	h := StructuralHypothesis{
		Proposer: "",
		Claim:    "some claim",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes:    map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{{NodeType: "technology", Label: "tech:X"}},
		},
	}

	out := ProposeExtension(r, h)

	require.False(t, out.Accepted)
	require.Error(t, out.Rejected)
	assert.Empty(t, r.Ancestors("tech:X"))
}

func TestProposeExtension_RejectsEmptyClaim(t *testing.T) {
	r := NewReasoner(NewMetrics())
	h := StructuralHypothesis{
		Proposer: "agent-run-4",
		Claim:    "",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes:    map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{{NodeType: "technology", Label: "tech:X"}},
		},
	}

	out := ProposeExtension(r, h)

	require.False(t, out.Accepted)
	require.Error(t, out.Rejected)
	assert.Empty(t, r.Ancestors("tech:X"))
}

// -----------------------------------------------------------------------
// Acceptance: accepted extensions register via RegisterExtension and
// survive replay (criterion 2) — the same StructuralHypothesis, applied
// again to a fresh Reasoner (simulating a replay from a persisted event),
// deterministically reproduces the identical registration.
// -----------------------------------------------------------------------

func TestProposeExtension_ReplayIsDeterministic(t *testing.T) {
	h := StructuralHypothesis{
		Proposer: "agent-run-5",
		Claim:    "iis hosts should subclass web-server",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:IIS", SubClassOf: "tech:WebServer"},
			},
			IFPs: []sdkgraphrag.IFPDef{{NodeType: "technology", Property: "cpe"}},
		},
	}

	r1 := NewReasoner(NewMetrics())
	out1 := ProposeExtension(r1, h)

	r2 := NewReasoner(NewMetrics())
	out2 := ProposeExtension(r2, h)

	require.True(t, out1.Accepted)
	require.True(t, out2.Accepted)
	assert.Equal(t, out1.ExtensionName, out2.ExtensionName)
	assert.Equal(t, r1.Ancestors("tech:IIS"), r2.Ancestors("tech:IIS"))
	assert.Equal(t, r1.IFPsForType("technology"), r2.IFPsForType("technology"))
}

func TestProposeExtension_SameProposerSameContentIsIdempotent(t *testing.T) {
	r := NewReasoner(NewMetrics())
	h := StructuralHypothesis{
		Proposer: "agent-run-6",
		Claim:    "iis hosts should subclass web-server",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:IIS", SubClassOf: "tech:WebServer"},
			},
		},
	}

	out1 := ProposeExtension(r, h)
	out2 := ProposeExtension(r, h)

	require.True(t, out1.Accepted)
	require.True(t, out2.Accepted)
	assert.Equal(t, out1.ExtensionName, out2.ExtensionName)
	assert.Equal(t, []string{"tech:WebServer"}, r.Ancestors("tech:IIS"))
}

func TestProposeExtension_DifferentProposersMergeWithoutColliding(t *testing.T) {
	r := NewReasoner(NewMetrics())

	h1 := StructuralHypothesis{
		Proposer: "agent-run-7",
		Claim:    "iis hosts should subclass web-server",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:IIS", SubClassOf: "tech:WebServer"},
			},
		},
	}
	h2 := StructuralHypothesis{
		Proposer: "agent-run-8",
		Claim:    "apache hosts should subclass web-server",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:Apache", SubClassOf: "tech:WebServer"},
			},
		},
	}

	out1 := ProposeExtension(r, h1)
	out2 := ProposeExtension(r, h2)

	require.True(t, out1.Accepted)
	require.True(t, out2.Accepted)
	assert.NotEqual(t, out1.ExtensionName, out2.ExtensionName)
	assert.Contains(t, r.Ancestors("tech:IIS"), "tech:WebServer")
	assert.Contains(t, r.Ancestors("tech:Apache"), "tech:WebServer")
}

func TestProposeExtension_EquivalenceContentDiffersFromHierarchy(t *testing.T) {
	// Two proposals from the same proposer with the same "claim" text but
	// different structural content (a class vs. a relationship/equivalence)
	// must not collide on extension name — the name is a function of the
	// full proposed content, not just Proposer+Claim.
	r := NewReasoner(NewMetrics())
	base := StructuralHypothesis{
		Proposer: "agent-run-9",
		Claim:    "duplicate claim text, different content",
	}

	h1 := base
	h1.Extension = sdkgraphrag.OntologyExtension{
		Prefixes:    map[string]string{"tech": "https://example.com/tech#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{{NodeType: "technology", Label: "tech:X"}},
	}
	h2 := base
	h2.Extension = sdkgraphrag.OntologyExtension{
		Prefixes:     map[string]string{"tech": "https://example.com/tech#", "cve": "https://example.com/cve#"},
		Equivalences: [][2]string{{"tech:X", "cve:CVE-1"}},
	}

	out1 := ProposeExtension(r, h1)
	out2 := ProposeExtension(r, h2)

	require.True(t, out1.Accepted)
	require.True(t, out2.Accepted)
	assert.NotEqual(t, out1.ExtensionName, out2.ExtensionName)
}

// -----------------------------------------------------------------------
// canonicalExtensionString's sort comparators only execute their branches
// when a field carries two or more entries whose ordering actually differs
// across every tie-break tier, and RawTriples only hashes when non-empty.
// These were 0%-covered: every earlier test proposed at most one entry per
// field. Exercise all of them together, in reverse/shuffled order between
// two semantically-identical extensions, and assert the canonical hash is
// still order-independent — the property canonicalExtensionString exists
// to guarantee.
// -----------------------------------------------------------------------

func TestProposeExtension_CanonicalHashIsOrderIndependentAcrossEveryField(t *testing.T) {
	extInOrder := sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{"a": "urn:a#", "b": "urn:b#", "c": "urn:c#", "d": "urn:d#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			// Same NodeType+Label, differing SubClassOf only (exercises the
			// comparator's final tie-break tier).
			{NodeType: "x", Label: "a:One", SubClassOf: "a:Base"},
			{NodeType: "x", Label: "a:One", SubClassOf: "a:Root"},
			// Same NodeType, differing Label (exercises the comparator's
			// middle tie-break tier).
			{NodeType: "x", Label: "a:Three"},
			// Differing NodeType (exercises the comparator's first tier).
			{NodeType: "y", Label: "a:Two"},
		},
		Equivalences: [][2]string{
			// Same first element after normalisation, differing second
			// (exercises the comparator's second tie-break tier).
			{"a:One", "b:Alpha"},
			{"a:One", "b:Beta"},
			// Differing first element (exercises the comparator's first tier).
			{"c:Gamma", "d:Delta"},
		},
		IFPs: []sdkgraphrag.IFPDef{
			// Same NodeType, differing Property (second tier).
			{NodeType: "x", Property: "id"},
			{NodeType: "x", Property: "uid"},
			// Differing NodeType (first tier).
			{NodeType: "z", Property: "name"},
		},
		RawTriples: []byte("some raw turtle payload"),
	}

	// Semantically identical content, entries reversed/shuffled and one
	// equivalence pair's own two elements swapped (sameAs is symmetric, so
	// {"b:Beta","a:One"} must normalise to the same canonical form as
	// {"a:One","b:Beta"}).
	extShuffled := sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{"b": "urn:b#", "a": "urn:a#", "d": "urn:d#", "c": "urn:c#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			{NodeType: "y", Label: "a:Two"},
			{NodeType: "x", Label: "a:Three"},
			{NodeType: "x", Label: "a:One", SubClassOf: "a:Root"},
			{NodeType: "x", Label: "a:One", SubClassOf: "a:Base"},
		},
		Equivalences: [][2]string{
			{"c:Gamma", "d:Delta"},
			{"b:Beta", "a:One"},
			{"a:One", "b:Alpha"},
		},
		IFPs: []sdkgraphrag.IFPDef{
			{NodeType: "z", Property: "name"},
			{NodeType: "x", Property: "uid"},
			{NodeType: "x", Property: "id"},
		},
		RawTriples: []byte("some raw turtle payload"),
	}

	r1 := NewReasoner(NewMetrics())
	r2 := NewReasoner(NewMetrics())

	out1 := ProposeExtension(r1, StructuralHypothesis{Proposer: "agent", Claim: "c", Extension: extInOrder})
	out2 := ProposeExtension(r2, StructuralHypothesis{Proposer: "agent", Claim: "c", Extension: extShuffled})

	require.True(t, out1.Accepted)
	require.True(t, out2.Accepted)
	assert.Equal(t, out1.ExtensionName, out2.ExtensionName)

	// A third proposal with different RawTriples content (everything else
	// identical) must hash differently — RawTriples participates in the
	// canonical form.
	extDifferentRaw := extInOrder
	extDifferentRaw.RawTriples = []byte("a completely different payload")
	r3 := NewReasoner(NewMetrics())
	out3 := ProposeExtension(r3, StructuralHypothesis{Proposer: "agent", Claim: "c", Extension: extDifferentRaw})
	require.True(t, out3.Accepted)
	assert.NotEqual(t, out1.ExtensionName, out3.ExtensionName)
}

// -----------------------------------------------------------------------
// Identity boundary (gibson#484): ontology discovery is DATA-LEVEL and never
// produces a Neo4j node label, so it has no written key form to assign — the
// natural-key rule gibson#484 enforces at promotion applies to taxonomy
// node-label promotion (gibson#281, taxonomy.PromotionGate), not here.
//
// ADR-0124 draws this line: a proposed ontology class is a prefix:localname
// IRI the Reasoner reasons OVER, never a Cypher query token. These tests make
// that boundary executable, so a later change that tried to route an ontology
// class into node-label structure (where it WOULD need a collision-proof key,
// gibson#1669/#486) fails here first.
// -----------------------------------------------------------------------

// An ontology class label is a prefix:localname IRI. The prefix separator is a
// character taxonomy.ValidIdentifier refuses, so an ontology class is
// structurally incapable of being a Neo4j node label: it can never reach Cypher
// as an identifier and so never needs the gibson#484 key form.
func TestProposeExtension_OntologyClassIsNotAValidTaxonomyNodeLabel(t *testing.T) {
	r := NewReasoner(NewMetrics())

	h := StructuralHypothesis{
		Proposer: "agent-run-boundary",
		Claim:    "iot devices subclass hosts",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:IoTDevice", SubClassOf: "tech:Host"},
			},
		},
	}

	out := ProposeExtension(r, h)
	require.True(t, out.Accepted)

	// Every class label the accepted extension introduced is a prefixed IRI
	// that cannot pass the taxonomy node-label safety gate.
	for _, hier := range h.Extension.Hierarchies {
		require.Error(t, taxonomy.ValidIdentifier(hier.Label),
			"ontology class %q must NOT be a valid taxonomy node label", hier.Label)
		require.Error(t, taxonomy.ValidIdentifier(hier.SubClassOf),
			"ontology parent class %q must NOT be a valid taxonomy node label", hier.SubClassOf)
	}
}

// Registering an ontology extension adds Reasoner vocabulary only. It does not
// promote anything into the taxonomy node-label set, so the taxonomy's
// collision-proof keying (gibson#484) is never engaged by ontology discovery.
func TestProposeExtension_DoesNotTouchTaxonomyNodeLabels(t *testing.T) {
	r := NewReasoner(NewMetrics())

	before := append([]string(nil), taxonomy.Global.NodeLabels()...)

	out := ProposeExtension(r, StructuralHypothesis{
		Proposer: "agent-run-boundary",
		Claim:    "a new technology class",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes: map[string]string{"tech": "https://example.com/tech#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{
				{NodeType: "technology", Label: "tech:MessageQueue", SubClassOf: "tech:Service"},
			},
		},
	})
	require.True(t, out.Accepted)

	// The global taxonomy node-label vocabulary is untouched: ontology and
	// taxonomy are separate vocabularies (ADR-0124).
	assert.Equal(t, before, taxonomy.Global.NodeLabels())
}
