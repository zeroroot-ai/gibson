// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// -----------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------

func TestBeliefSchemaRegistry_EmptyByDefault(t *testing.T) {
	reg := NewBeliefSchemaRegistry()

	assert.False(t, reg.IsBeliefBearing("Host"))
	assert.Empty(t, reg.Variables("Host"))
	assert.Empty(t, reg.BeliefBearingNodeTypes())
	assert.False(t, reg.IsEnablementEdge("RESOLVES_TO"))
	assert.Empty(t, reg.EnablementEdgeTypes())
}

func TestBeliefSchemaRegistry_RegisterExtension_MakesNodeBeliefBearing(t *testing.T) {
	reg := NewBeliefSchemaRegistry()

	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{
				NodeType: "Host",
				Variables: []BeliefVariable{
					{Name: "reachable"},
					{Name: "exploitable", DependsOn: []string{"reachable"}},
					{Name: "juicy", DependsOn: []string{"exploitable"}},
				},
			},
		},
		EnablementEdges: []string{"RESOLVES_TO"},
	})
	require.NoError(t, err)

	assert.True(t, reg.IsBeliefBearing("Host"))
	assert.False(t, reg.IsBeliefBearing("Finding"))
	assert.Equal(t, []string{"Host"}, reg.BeliefBearingNodeTypes())

	vars := reg.Variables("Host")
	require.Len(t, vars, 3)
	byName := make(map[string][]string, len(vars))
	for _, v := range vars {
		byName[v.Name] = v.DependsOn
	}
	assert.Contains(t, byName, "reachable")
	assert.Equal(t, []string{"reachable"}, byName["exploitable"])
	assert.Equal(t, []string{"exploitable"}, byName["juicy"])

	assert.True(t, reg.IsEnablementEdge("RESOLVES_TO"))
	assert.False(t, reg.IsEnablementEdge("AFFECTS"))
	assert.Equal(t, []string{"RESOLVES_TO"}, reg.EnablementEdgeTypes())
}

func TestBeliefSchemaRegistry_Variables_ReturnsDefensiveCopy(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	}))

	vars := reg.Variables("Host")
	vars[0].Name = "mutated"
	vars = append(vars, BeliefVariable{Name: "injected"})

	fresh := reg.Variables("Host")
	require.Len(t, fresh, 1)
	assert.Equal(t, "reachable", fresh[0].Name)
}

func TestBeliefSchemaRegistry_BeliefBearingNodeTypes_Sorted(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Service", Variables: []BeliefVariable{{Name: "reachable"}}},
			{NodeType: "Domain", Variables: []BeliefVariable{{Name: "reachable"}}},
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	}))

	assert.Equal(t, []string{"Domain", "Host", "Service"}, reg.BeliefBearingNodeTypes())
}

func TestBeliefSchemaRegistry_EnablementEdgeTypes_Sorted(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		EnablementEdges: []string{"RUNS_SERVICE", "AFFECTS", "ISSUED"},
	}))

	assert.Equal(t, []string{"AFFECTS", "ISSUED", "RUNS_SERVICE"}, reg.EnablementEdgeTypes())
}

// -----------------------------------------------------------------------
// Multiple extensions merge additively (ADR-0024 discoverable ontology: a
// later Pack extends the schema without a code change to an earlier one).
// -----------------------------------------------------------------------

func TestBeliefSchemaRegistry_MultipleExtensions_MergeAdditively(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
		EnablementEdges: []string{"RESOLVES_TO"},
	}))
	require.NoError(t, reg.RegisterExtension("pack/webapp", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Finding", Variables: []BeliefVariable{{Name: "confirmed"}}},
		},
		EnablementEdges: []string{"AFFECTS"},
	}))

	assert.ElementsMatch(t, []string{"Host", "Finding"}, reg.BeliefBearingNodeTypes())
	assert.ElementsMatch(t, []string{"RESOLVES_TO", "AFFECTS"}, reg.EnablementEdgeTypes())
}

func TestBeliefSchemaRegistry_UnregisterExtension_RemovesItsContributions(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
		EnablementEdges: []string{"RESOLVES_TO"},
	}))
	require.NoError(t, reg.RegisterExtension("pack/webapp", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Finding", Variables: []BeliefVariable{{Name: "confirmed"}}},
		},
	}))

	require.NoError(t, reg.UnregisterExtension("pack/webapp"))

	assert.True(t, reg.IsBeliefBearing("Host"))
	assert.False(t, reg.IsBeliefBearing("Finding"))
}

func TestBeliefSchemaRegistry_UnregisterExtension_UnknownNameIsNoop(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.UnregisterExtension("does-not-exist"))
}

func TestBeliefSchemaRegistry_ReRegisterSameName_Replaces(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	}))
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Domain", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	}))

	assert.False(t, reg.IsBeliefBearing("Host"))
	assert.True(t, reg.IsBeliefBearing("Domain"))
}

// -----------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------

func TestBeliefSchemaRegistry_RejectsEmptyNodeType(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	})
	require.Error(t, err)
}

func TestBeliefSchemaRegistry_RejectsInvalidNodeTypeIdentifier(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Ho st", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	})
	require.Error(t, err)
}

func TestBeliefSchemaRegistry_RejectsNodeWithNoVariables(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: nil},
		},
	})
	require.Error(t, err)
}

func TestBeliefSchemaRegistry_RejectsDuplicateVariableNameSameExtension(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{
				{Name: "reachable"},
				{Name: "reachable"},
			}},
		},
	})
	require.Error(t, err)
}

func TestBeliefSchemaRegistry_RejectsDuplicateVariableNameAcrossExtensions(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	}))
	err := reg.RegisterExtension("pack/other", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
		},
	})
	require.Error(t, err)

	// The rejected extension must not have partially applied.
	vars := reg.Variables("Host")
	require.Len(t, vars, 1)
}

func TestBeliefSchemaRegistry_RejectsUnknownDependency(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{
				{Name: "juicy", DependsOn: []string{"does_not_exist"}},
			}},
		},
	})
	require.Error(t, err)
}

func TestBeliefSchemaRegistry_RejectsDependencyOnAnotherNodeType(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{{Name: "reachable"}}},
			{NodeType: "Finding", Variables: []BeliefVariable{
				{Name: "confirmed", DependsOn: []string{"reachable"}},
			}},
		},
	})
	require.Error(t, err)
}

func TestBeliefSchemaRegistry_RejectsCyclicVariableDependency(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{NodeType: "Host", Variables: []BeliefVariable{
				{Name: "a", DependsOn: []string{"b"}},
				{Name: "b", DependsOn: []string{"a"}},
			}},
		},
	})
	require.Error(t, err)
	var cycleErr *VariableCycleError
	assert.ErrorAs(t, err, &cycleErr)
}

func TestBeliefSchemaRegistry_RejectsInvalidEnablementEdgeIdentifier(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	err := reg.RegisterExtension("core", BeliefSchemaExtension{
		EnablementEdges: []string{"not an identifier"},
	})
	require.Error(t, err)
}

func TestBeliefSchemaRegistry_DuplicateEnablementEdgeAcrossExtensions_IsBenign(t *testing.T) {
	// Two Packs independently flagging the same edge type as enablement is
	// not a conflict — unlike variable declarations, there is no competing
	// payload to reconcile.
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core", BeliefSchemaExtension{
		EnablementEdges: []string{"RESOLVES_TO"},
	}))
	require.NoError(t, reg.RegisterExtension("pack/other", BeliefSchemaExtension{
		EnablementEdges: []string{"RESOLVES_TO"},
	}))
	assert.Equal(t, []string{"RESOLVES_TO"}, reg.EnablementEdgeTypes())
}

// -----------------------------------------------------------------------
// Seed content (ADR-0029 §2, §7)
// -----------------------------------------------------------------------

func TestSeedBeliefSchemaExtension_HostIsBeliefBearingWithThreeVariables(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", SeedBeliefSchemaExtension()))

	require.True(t, reg.IsBeliefBearing("Host"))
	vars := reg.Variables("Host")
	names := make([]string, 0, len(vars))
	for _, v := range vars {
		names = append(names, v.Name)
	}
	assert.ElementsMatch(t, []string{"reachable", "exploitable", "juicy"}, names)
}

func TestSeedBeliefSchemaExtension_SeedsCoreEnablementEdges(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", SeedBeliefSchemaExtension()))

	for _, edge := range []string{"RESOLVES_TO", "ISSUED", "DELEGATED_TO", "RUNS_SERVICE", "AFFECTS"} {
		assert.Truef(t, reg.IsEnablementEdge(edge), "expected %s to be an enablement edge", edge)
	}
	assert.False(t, reg.IsEnablementEdge("HAS_PORT"))
	assert.False(t, reg.IsEnablementEdge("HAS_SUBDOMAIN"))
}

func TestSeedBeliefSchemaExtension_EnablementEdgesAreValidTaxonomyRelationshipTypes(t *testing.T) {
	// The seed must never flag an edge type that the projector cannot even
	// materialise — it would be an enablement flag on a relationship that
	// never appears in the graph.
	seed := SeedBeliefSchemaExtension()
	known := taxonomy.Global.RelationshipTypes()
	for _, edge := range seed.EnablementEdges {
		assert.Truef(t, slices.Contains(known, edge), "seed enablement edge %q is not a known taxonomy relationship type", edge)
	}
}

func TestRegisterCoreBeliefSchemaSeed_RegistersUnderCoreName(t *testing.T) {
	reg := NewBeliefSchemaRegistry()
	require.NoError(t, RegisterCoreBeliefSchemaSeed(reg))
	assert.True(t, reg.IsBeliefBearing("Host"))
}
