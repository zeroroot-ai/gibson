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
const d3fendPackName = "mitre-d3fend"

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
	var ids []string
	for _, c := range p.CountermeasuresFor("T1059") {
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
