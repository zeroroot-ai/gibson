// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// -----------------------------------------------------------------------
// terminalVariables
// -----------------------------------------------------------------------

func TestTerminalVariables_SingleChainReturnsTheSink(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", ontology.SeedBeliefSchemaExtension()))

	// Host's seed chain is reachable -> exploitable -> juicy: nothing depends
	// on "juicy", so it is the sole terminal.
	assert.Equal(t, []string{"juicy"}, terminalVariables(reg, "Host"))
}

func TestTerminalVariables_SingleVariableIsItsOwnTerminal(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("test", ontology.BeliefSchemaExtension{
		Nodes: []ontology.NodeBeliefSchema{
			{NodeType: "Finding", Variables: []ontology.BeliefVariable{{Name: "verified"}}},
		},
	}))
	assert.Equal(t, []string{"verified"}, terminalVariables(reg, "Finding"))
}

func TestTerminalVariables_MultipleSinksAreAllReturnedSorted(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("test", ontology.BeliefSchemaExtension{
		Nodes: []ontology.NodeBeliefSchema{
			{NodeType: "Widget", Variables: []ontology.BeliefVariable{
				{Name: "root"},
				{Name: "z_sink", DependsOn: []string{"root"}},
				{Name: "a_sink", DependsOn: []string{"root"}},
			}},
		},
	}))
	assert.Equal(t, []string{"a_sink", "z_sink"}, terminalVariables(reg, "Widget"))
}

func TestTerminalVariables_UnknownNodeKindReturnsEmpty(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	assert.Empty(t, terminalVariables(reg, "DoesNotExist"))
}

// -----------------------------------------------------------------------
// groundAttackGraph
// -----------------------------------------------------------------------

func TestGroundAttackGraph_IntraNodeDependsOnUsesUninformativePrior(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", ontology.SeedBeliefSchemaExtension()))

	graph := AttackGraph{
		Nodes: []AttackGraphNode{
			{InfraNode: InfraNode{ID: "host-a", Kind: "Host"}, Variables: reg.Variables("Host")},
		},
	}

	nodes, causes := groundAttackGraph(graph, reg)
	require.Empty(t, causes)
	require.Len(t, nodes, 1)
	require.Equal(t, "host-a", nodes[0].NodeID)

	exploitable, ok := nodes[0].Variables["exploitable"]
	require.True(t, ok)
	assert.InDelta(t, UninformativePriorStrength, exploitable.Leak, 1e-9)
	require.Contains(t, exploitable.DependsOn, "reachable")
	assert.InDelta(t, UninformativePriorStrength, exploitable.DependsOn["reachable"], 1e-9)

	reachable, ok := nodes[0].Variables["reachable"]
	require.True(t, ok)
	assert.InDelta(t, UninformativePriorStrength, reachable.Leak, 1e-9)
	assert.Empty(t, reachable.DependsOn)
}

func TestGroundAttackGraph_EnablementEdgeBecomesATerminalSourcedCause(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", ontology.SeedBeliefSchemaExtension()))

	graph := AttackGraph{
		Nodes: []AttackGraphNode{
			{InfraNode: InfraNode{ID: "host-a", Kind: "Host"}, Variables: reg.Variables("Host")},
			{InfraNode: InfraNode{ID: "host-b", Kind: "Host"}, Variables: reg.Variables("Host")},
		},
		Edges: []InfraEdge{{Type: "RESOLVES_TO", From: "host-a", To: "host-b"}},
	}

	_, causes := groundAttackGraph(graph, reg)
	require.Len(t, causes, 1)
	assert.Equal(t, beliefvi.EnablementCause{
		SourceNode:     "host-a",
		SourceVariable: "juicy", // host-a's terminal variable
		TargetNode:     "host-b",
		TargetVariable: "reachable", // RESOLVES_TO's declared target (seed)
		Strength:       UninformativePriorStrength,
	}, causes[0])
}

func TestGroundAttackGraph_SkipsAnEdgeWhoseTargetVariableTheDestinationDoesNotDeclare(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("test", ontology.BeliefSchemaExtension{
		Nodes: []ontology.NodeBeliefSchema{
			{NodeType: "Host", Variables: []ontology.BeliefVariable{{Name: "reachable"}}},
			{NodeType: "Finding", Variables: []ontology.BeliefVariable{{Name: "verified"}}},
		},
		// RESOLVES_TO targets "reachable", which Finding never declares.
		EnablementEdges: []ontology.EnablementEdgeSpec{{RelType: "RESOLVES_TO", TargetVariable: "reachable"}},
	}))

	graph := AttackGraph{
		Nodes: []AttackGraphNode{
			{InfraNode: InfraNode{ID: "host-a", Kind: "Host"}, Variables: reg.Variables("Host")},
			{InfraNode: InfraNode{ID: "finding-1", Kind: "Finding"}, Variables: reg.Variables("Finding")},
		},
		Edges: []InfraEdge{{Type: "RESOLVES_TO", From: "host-a", To: "finding-1"}},
	}

	_, causes := groundAttackGraph(graph, reg)
	assert.Empty(t, causes)
}

func TestGroundAttackGraph_SkipsAnEdgeTypeAbsentFromTheRegistry(t *testing.T) {
	// Defensive: groundAttackGraph does not assume its caller (normally
	// DeriveAttackGraph) already filtered graph.Edges to registered
	// enablement types.
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("test", ontology.BeliefSchemaExtension{
		Nodes: []ontology.NodeBeliefSchema{
			{NodeType: "Host", Variables: []ontology.BeliefVariable{{Name: "reachable"}}},
		},
	}))

	graph := AttackGraph{
		Nodes: []AttackGraphNode{
			{InfraNode: InfraNode{ID: "host-a", Kind: "Host"}, Variables: reg.Variables("Host")},
			{InfraNode: InfraNode{ID: "host-b", Kind: "Host"}, Variables: reg.Variables("Host")},
		},
		Edges: []InfraEdge{{Type: "NOT_REGISTERED", From: "host-a", To: "host-b"}},
	}

	_, causes := groundAttackGraph(graph, reg)
	assert.Empty(t, causes)
}

func TestGroundAttackGraph_MultipleTerminalsEachBecomeAnIndependentCause(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("test", ontology.BeliefSchemaExtension{
		Nodes: []ontology.NodeBeliefSchema{
			{NodeType: "Widget", Variables: []ontology.BeliefVariable{
				{Name: "root"},
				{Name: "sink_a", DependsOn: []string{"root"}},
				{Name: "sink_b", DependsOn: []string{"root"}},
			}},
			{NodeType: "Target", Variables: []ontology.BeliefVariable{{Name: "fed"}}},
		},
		EnablementEdges: []ontology.EnablementEdgeSpec{{RelType: "AFFECTS", TargetVariable: "fed"}},
	}))

	graph := AttackGraph{
		Nodes: []AttackGraphNode{
			{InfraNode: InfraNode{ID: "widget-1", Kind: "Widget"}, Variables: reg.Variables("Widget")},
			{InfraNode: InfraNode{ID: "target-1", Kind: "Target"}, Variables: reg.Variables("Target")},
		},
		Edges: []InfraEdge{{Type: "AFFECTS", From: "widget-1", To: "target-1"}},
	}

	_, causes := groundAttackGraph(graph, reg)
	require.Len(t, causes, 2)
	sourceVars := []string{causes[0].SourceVariable, causes[1].SourceVariable}
	sort.Strings(sourceVars)
	assert.Equal(t, []string{"sink_a", "sink_b"}, sourceVars)
	for _, c := range causes {
		assert.Equal(t, "widget-1", c.SourceNode)
		assert.Equal(t, "target-1", c.TargetNode)
		assert.Equal(t, "fed", c.TargetVariable)
		assert.InDelta(t, UninformativePriorStrength, c.Strength, 1e-9)
	}
}

// -----------------------------------------------------------------------
// nativeSliceBelief (SliceBeliefProvider)
// -----------------------------------------------------------------------

func TestNativeSliceBelief_ColdStartLoneNodeIsExactlyOneHalf(t *testing.T) {
	// ADR-0037 decision 3's acceptance criterion, direct: a node with no
	// causes at all (no intra-node parents, no incoming enablement edge)
	// grounds to a bare leak prior at UninformativePriorStrength — mean
	// exactly 0.5, never a hand-authored number.
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("test", ontology.BeliefSchemaExtension{
		Nodes: []ontology.NodeBeliefSchema{
			{NodeType: "Host", Variables: []ontology.BeliefVariable{{Name: "reachable"}}},
		},
	}))

	p := NativeSliceBeliefProvider(reg)
	graph := AttackGraph{Nodes: []AttackGraphNode{
		{InfraNode: InfraNode{ID: "host-a", Kind: "Host"}, Variables: reg.Variables("Host")},
	}}

	got := p.ScoreSlice(graph)
	require.Contains(t, got, "host-a")
	assert.InDelta(t, 0.5, got["host-a"].Belief.Reachable, 1e-12)
	assert.Equal(t, nativeSliceBeliefVersion, got["host-a"].Belief.Model)
}

func TestNativeSliceBelief_ScoreSlice_MatchesDirectBeliefviSolve(t *testing.T) {
	// Wiring-correctness test: whatever groundAttackGraph builds from the
	// AttackGraph must be exactly what beliefvi.SolveSlice is handed —
	// checked here by comparing the provider's output against a direct
	// SolveSlice call over the same NodeSpec/EnablementCause shape, rather
	// than hand-deriving noisy-OR arithmetic (beliefvi's own tests already
	// hold that math to the pgmpy parity oracle).
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", ontology.SeedBeliefSchemaExtension()))

	graph := AttackGraph{
		Nodes: []AttackGraphNode{
			{InfraNode: InfraNode{ID: "host-a", Kind: "Host"}, Variables: reg.Variables("Host")},
			{InfraNode: InfraNode{ID: "host-b", Kind: "Host"}, Variables: reg.Variables("Host")},
		},
		Edges: []InfraEdge{{Type: "RESOLVES_TO", From: "host-a", To: "host-b"}},
	}

	nodes, causes := groundAttackGraph(graph, reg)
	want, err := beliefvi.SolveSlice(nodes, causes, nil)
	require.NoError(t, err)

	p := NativeSliceBeliefProvider(reg)
	got := p.ScoreSlice(graph)

	for _, id := range []string{"host-a", "host-b"} {
		require.Contains(t, got, id)
		assert.InDelta(t, want[id]["reachable"].True, got[id].Belief.Reachable, 1e-12, id)
		assert.InDelta(t, want[id]["exploitable"].True, got[id].Belief.Exploitable, 1e-12, id)
		assert.InDelta(t, want[id]["juicy"].True, got[id].Belief.Juicy, 1e-12, id)
	}
	// host-b's reachable must be pulled above the bare 0.5 cold-start by
	// host-a's incoming enablement cause — belief propagates, not just sits
	// at a flat, structure-blind prior.
	assert.Greater(t, got["host-b"].Belief.Reachable, 0.5)
}

func TestNativeSliceBelief_Version(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	p := NativeSliceBeliefProvider(reg)
	assert.Equal(t, "native-slice-v0-uninformative-prior", p.Version())
}
