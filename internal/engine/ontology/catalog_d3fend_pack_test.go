// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// d3fendPackName is the catalog name of the MITRE D3FEND pack.
const d3fendPackName = D3FENDPackName

func d3fendPack(t *testing.T) DomainPack {
	t.Helper()
	p, ok := EmbeddedCatalog().Get(d3fendPackName)
	require.True(t, ok, "the embedded catalog must hold the D3FEND pack")
	return p
}

func TestD3FENDPack_IsValidAndNamesItsRelease(t *testing.T) {
	p := d3fendPack(t)
	require.NoError(t, p.Validate())
	assert.Equal(t, PackVisibilityPublic, p.Visibility)
	require.NotNil(t, p.Source)
	assert.Equal(t, "MITRE D3FEND", p.Source.Name)
	assert.Equal(t, "1.6.0", p.Source.Release)
	assert.Equal(t, "https://d3fend.mitre.org/ontologies/d3fend.json", p.Source.URL)
	assert.NotEmpty(t, p.Source.License)
	assert.NotEmpty(t, p.Source.SHA256)
	assert.NotEmpty(t, p.Countermeasures)
}

// TestD3FENDPack_AQueryReturnsTheCountermeasuresOfATechnique: T1059 is
// Command and Scripting Interpreter. D3FEND maps File Analysis to it.
func TestD3FENDPack_AQueryReturnsTheCountermeasuresOfATechnique(t *testing.T) {
	p := d3fendPack(t)
	cms := p.CountermeasuresFor("T1059")
	ids := make([]string, 0, len(cms))
	for _, c := range cms {
		ids = append(ids, c.ID)
	}
	assert.Contains(t, ids, "D3-FA")
	assert.Empty(t, p.CountermeasuresFor("T0000"))
}

func TestD3FENDPack_HierarchyHasATacticAboveEachCountermeasure(t *testing.T) {
	p := d3fendPack(t)
	assert.ElementsMatch(t, []string{"Deceive", "Detect", "Evict", "Harden", "Isolate", "Model", "Restore"},
		p.CountermeasureTactics)
	fa, ok := p.Countermeasure("D3-FA")
	require.True(t, ok)
	assert.Equal(t, "Detect", fa.Tactic)
}

// TestD3FENDPack_ImportPromotesItsLabelAndEdges: the pack carries the label
// and the relationship types, so the Taxonomy needs no code change for them.
func TestD3FENDPack_ImportPromotesItsLabelAndEdges(t *testing.T) {
	p := d3fendPack(t)
	reg, err := p.Import(taxonomy.Global, NewReasoner(nil))
	require.NoError(t, err)
	assert.True(t, reg.ClassifyNode(CountermeasureLabel).InTaxonomy)
	assert.True(t, reg.ClassifyRelationship(CountersRelationshipType).InTaxonomy)
	assert.True(t, reg.ClassifyRelationship(AppliesCountermeasureRelationshipType).InTaxonomy)
}

// TestD3FENDPack_HoldsNoPredicate: the pack in the catalog holds no
// predicate (gibson#1485). The guard keys on the pack name.
func TestD3FENDPack_HoldsNoPredicate(t *testing.T) {
	p := d3fendPack(t)
	assert.Empty(t, p.Predicates)
	assert.Empty(t, p.NonDestructivePredicates)
	assert.Equal(t, D3FENDPackName, p.Name)
}

// TestD3FENDPack_RefusesAPredicate is the failing fixture of the guard: a
// copy of the pack with one predicate fails Validate, and so the catalog
// refuses it. The same predicate in a pack with another name is valid.
func TestD3FENDPack_RefusesAPredicate(t *testing.T) {
	fixture := d3fendPack(t)
	fixture.Predicates = map[string]string{"privileged_container_detected": `markerPresent(evidence, "X")`}
	fixture.Techniques = map[string]string{"privileged_container_detected": "privilege_escalation"}

	err := fixture.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no predicate")
	assert.Panics(t, func() { NewDomainPackCatalog(fixture) })

	// The guard keys on the content: a pack of countermeasures with another
	// name is refused too, and so is a mapping rule in it (review m21).
	other := fixture
	other.Name = "other-pack"
	require.Error(t, other.Validate(), "the guard keys on the content, not on the name")
	rules := d3fendPack(t)
	rules.MappingRules = []MappingRule{{ControlID: "ac-2", Expression: "true"}}
	require.Error(t, rules.Validate(), "a mapping rule in a pack of countermeasures")
	plain := fixture
	plain.Countermeasures, plain.CountermeasureTactics = nil, nil
	plain.Name = "other-pack"
	require.NoError(t, plain.Validate(), "a pack with no countermeasure keeps its predicates")

	listed := d3fendPack(t)
	listed.NonDestructivePredicates = []string{"x"}
	require.Error(t, listed.Validate())
}
