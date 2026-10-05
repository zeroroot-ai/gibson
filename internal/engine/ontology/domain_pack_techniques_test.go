// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// TestMainDomainPack_TechniquesRollUpToTheirCategories proves the rollup: the
// core hierarchy holds no technique, and after the main pack extends it,
// each technique of the pack resolves to its category.
func TestMainDomainPack_TechniquesRollUpToTheirCategories(t *testing.T) {
	pack := MainDomainPack()
	require.NotEmpty(t, pack.Techniques, "the main pack must declare one technique or more")
	require.Empty(t, taxonomy.GlobalTechniques.Techniques(), "the core hierarchy holds categories only")

	extended, err := pack.ExtendTechniques(taxonomy.GlobalTechniques)
	require.NoError(t, err)

	want := map[taxonomy.TechniqueID]taxonomy.CategoryID{
		"unauthenticated_endpoint_exposed": "reconnaissance",
		"credential_disclosure_detected":   "extraction",
		"prompt_injection_marker_present":  "prompt_injection",
	}
	assert.Len(t, extended.Techniques(), len(want))
	for technique, category := range want {
		got, ok := extended.CategoryOf(technique)
		require.Truef(t, ok, "technique %q must be in the hierarchy", technique)
		assert.Equalf(t, category, got, "technique %q", technique)
	}

	// The core hierarchy is not changed.
	assert.Empty(t, taxonomy.GlobalTechniques.Techniques())
}

// TestMainDomainPack_EachPredicateIsBoundToADeclaredTechnique: the predicate
// of the pack and the technique of the pack use one name.
func TestMainDomainPack_EachPredicateIsBoundToADeclaredTechnique(t *testing.T) {
	pack := MainDomainPack()
	for technique := range pack.Predicates {
		assert.Containsf(t, pack.Techniques, technique, "predicate %q has no declared technique", technique)
	}
}

func TestDomainPack_ExtendTechniques(t *testing.T) {
	t.Run("a pack with no technique returns the base", func(t *testing.T) {
		pack := DomainPack{Name: "empty"}
		got, err := pack.ExtendTechniques(taxonomy.GlobalTechniques)
		require.NoError(t, err)
		assert.Same(t, taxonomy.GlobalTechniques, got)
	})
	t.Run("a category that the hierarchy does not admit is refused", func(t *testing.T) {
		pack := DomainPack{Name: "bad", Techniques: map[string]string{"t1": "no_such_category"}}
		_, err := pack.ExtendTechniques(taxonomy.GlobalTechniques)
		require.ErrorContains(t, err, "not admitted")
		require.ErrorContains(t, pack.Validate(), "not admitted")
	})
	t.Run("a technique id that is not a plain identifier is refused", func(t *testing.T) {
		pack := DomainPack{Name: "bad", Techniques: map[string]string{"bad id`": "extraction"}}
		require.Error(t, pack.Validate())
	})
	t.Run("a technique that the hierarchy already holds is refused", func(t *testing.T) {
		pack := DomainPack{Name: "p", Techniques: map[string]string{"t1": "extraction"}}
		once, err := pack.ExtendTechniques(taxonomy.GlobalTechniques)
		require.NoError(t, err)
		_, err = pack.ExtendTechniques(once)
		require.ErrorContains(t, err, "duplicate technique")
	})
}

// TestMainDomainPack_BeliefSchemaRegistersOnTheCoreSeed: with the pack, a web
// endpoint bears belief and EXPOSES is an enablement edge. Without the pack,
// neither is true.
func TestMainDomainPack_BeliefSchemaRegistersOnTheCoreSeed(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, RegisterCoreBeliefSchemaSeed(reg))
	require.False(t, reg.IsBeliefBearing("WebEndpoint"))
	require.False(t, reg.IsEnablementEdge("EXPOSES"))

	pack := MainDomainPack()
	require.NotNil(t, pack.BeliefSchema)
	require.NoError(t, pack.RegisterBeliefSchema(reg))

	assert.True(t, reg.IsBeliefBearing("WebEndpoint"))
	assert.True(t, reg.IsBeliefBearing("Host"), "the core seed stays")
	variable, ok := reg.EnablementEdgeTargetVariable("EXPOSES")
	require.True(t, ok)
	assert.Equal(t, "reachable", variable)
	names := make([]string, 0, 2)
	for _, v := range reg.Variables("WebEndpoint") {
		names = append(names, v.Name)
	}
	assert.ElementsMatch(t, []string{"reachable", "exploitable"}, names)
}

func TestDomainPack_BeliefSchema(t *testing.T) {
	t.Run("a pack with no extension registers nothing", func(t *testing.T) {
		reg := NewBeliefSchemaRegistry()
		pack := DomainPack{Name: "none"}
		require.NoError(t, pack.RegisterBeliefSchema(reg))
		assert.Empty(t, reg.BeliefBearingNodeTypes())
		require.NoError(t, pack.Validate())
	})
	t.Run("an extension with an unknown dependency fails Validate", func(t *testing.T) {
		pack := DomainPack{Name: "bad", BeliefSchema: &BeliefSchemaExtension{
			Nodes: []NodeBeliefSchema{{NodeType: "Thing", Variables: []BeliefVariable{
				{Name: "a", DependsOn: []string{"missing"}},
			}}},
		}}
		require.ErrorContains(t, pack.Validate(), "belief schema")
	})
	t.Run("an edge that conflicts with the core seed fails Validate", func(t *testing.T) {
		// The core seed says that RESOLVES_TO feeds "reachable".
		pack := DomainPack{Name: "bad", BeliefSchema: &BeliefSchemaExtension{
			EnablementEdges: []EnablementEdgeSpec{{RelType: "RESOLVES_TO", TargetVariable: "juicy"}},
		}}
		require.ErrorContains(t, pack.Validate(), "belief schema")
	})
	t.Run("two packs register under two names", func(t *testing.T) {
		reg := NewBeliefSchemaRegistry()
		a := DomainPack{Name: "a", BeliefSchema: &BeliefSchemaExtension{
			Nodes: []NodeBeliefSchema{{NodeType: "A", Variables: []BeliefVariable{{Name: "x"}}}},
		}}
		b := DomainPack{Name: "b", BeliefSchema: &BeliefSchemaExtension{
			Nodes: []NodeBeliefSchema{{NodeType: "B", Variables: []BeliefVariable{{Name: "y"}}}},
		}}
		require.NoError(t, a.RegisterBeliefSchema(reg))
		require.NoError(t, b.RegisterBeliefSchema(reg))
		assert.True(t, reg.IsBeliefBearing("A"))
		assert.True(t, reg.IsBeliefBearing("B"))
	})
}

// TestDomainPack_TechniquesAndBeliefSchemaSurviveJSON: a pack moves between
// installs as JSON, and the two new fields move with it.
func TestDomainPack_TechniquesAndBeliefSchemaSurviveJSON(t *testing.T) {
	pack := MainDomainPack()
	raw, err := json.Marshal(pack)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"techniques"`)
	assert.Contains(t, string(raw), `"belief_schema"`)
	assert.Contains(t, string(raw), `"enablement_edges"`)

	var back DomainPack
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, pack, back)
	require.NoError(t, back.Validate())
}
