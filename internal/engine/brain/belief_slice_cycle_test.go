// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cycleGraph is three hosts in a cycle: 1 enables 2, 2 enables 3, 3 enables 1.
func cycleInfra() ([]InfraNode, []InfraEdge) {
	nodes := []InfraNode{{ID: "1", Kind: "Host"}, {ID: "2", Kind: "Host"}, {ID: "3", Kind: "Host"}}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "1", To: "2"},
		{Type: "RESOLVES_TO", From: "2", To: "3"},
		{Type: "RESOLVES_TO", From: "3", To: "1"},
	}
	return nodes, edges
}

func slicePotentialsIncrease(g AttackGraph) bool {
	potential := map[string]int{}
	for _, n := range g.Nodes {
		potential[n.ID] = n.Potential
	}
	for _, e := range g.Edges {
		if potential[e.From] >= potential[e.To] {
			return false
		}
	}
	return true
}

// The acceptance test of gibson#700: the cut of the whole graph removes the
// edge 3 -> 1, and the slice of host 1 keeps it, because inside that slice the
// edge makes no cycle.
func TestExtractBoundedSlice_KeepsAnEdgeThatTheGlobalCutRemoved(t *testing.T) {
	registry := liveBeliefRegistry(t)
	nodes, edges := cycleInfra()
	back := InfraEdge{Type: "RESOLVES_TO", From: "3", To: "1"}

	global := DeriveAttackGraph(nodes, edges, registry)
	require.Contains(t, global.Dropped, back, "the global cut removes the edge 3 -> 1")
	require.NotContains(t, global.Edges, back)

	slice := ExtractBoundedSlice(EnablementGraph(nodes, edges, registry), "1", SliceOptions{MaxDepth: 1}, nil)
	require.Equal(t, []InfraEdge{back}, slice.Edges, "the slice of host 1 keeps the edge 3 -> 1")
	require.Empty(t, slice.Dropped)
	require.True(t, slicePotentialsIncrease(slice))
}

// A slice that holds the whole cycle breaks it: the result is acyclic and the
// cut edge is in Dropped.
func TestExtractBoundedSlice_BreaksACycleInsideTheSlice(t *testing.T) {
	registry := liveBeliefRegistry(t)
	nodes, edges := cycleInfra()

	slice := ExtractBoundedSlice(EnablementGraph(nodes, edges, registry), "1", SliceOptions{MaxDepth: 5}, nil)
	require.Len(t, slice.Nodes, 3)
	require.True(t, slicePotentialsIncrease(slice))
	// The edge out of the target closes the cycle, so it goes, and both edges
	// on the path into the target stay.
	assert.Equal(t, []InfraEdge{
		{Type: "RESOLVES_TO", From: "2", To: "3"},
		{Type: "RESOLVES_TO", From: "3", To: "1"},
	}, slice.Edges)
	assert.Equal(t, []InfraEdge{{Type: "RESOLVES_TO", From: "1", To: "2"}}, slice.Dropped)

	// The same input in another order gives the same edges.
	slices.Reverse(edges)
	again := ExtractBoundedSlice(EnablementGraph(nodes, edges, registry), "1", SliceOptions{MaxDepth: 5}, nil)
	assert.Equal(t, slice.Edges, again.Edges)
	assert.Equal(t, slice.Dropped, again.Dropped)
}

// DeriveAttackGraph is EnablementGraph plus BreakCycles.
func TestDeriveAttackGraph_IsTheEnablementGraphWithItsCyclesCut(t *testing.T) {
	registry := liveBeliefRegistry(t)
	nodes, edges := cycleInfra()
	derived := DeriveAttackGraph(nodes, edges, registry)
	cut := BreakCycles(EnablementGraph(nodes, edges, registry))
	assert.Equal(t, derived.Edges, cut.Edges)
	assert.Equal(t, derived.Dropped, cut.Dropped)

	uncut := EnablementGraph(nodes, edges, registry)
	assert.Len(t, uncut.Edges, 3, "the enablement graph cuts nothing")
	assert.Empty(t, uncut.Dropped)
}

// The live round settles on a cyclic World and scores each host. Before
// gibson#700 the slice code required an acyclic input.
func TestSliceBeliefRound_ACycleOfHostsSettles(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	for _, addr := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		e.Submit(HostObserved{ScopeID: "s", Address: addr, OpenPorts: []int{22}})
	}
	settle(e, bw, 1)
	a, b, c := hostIDAt(t, e, "10.0.0.1"), hostIDAt(t, e, "10.0.0.2"), hostIDAt(t, e, "10.0.0.3")
	linkHosts(e, a, b)
	linkHosts(e, b, c)
	linkHosts(e, c, a)
	e.Tick()

	registry := liveBeliefRegistry(t)
	gate := NewSliceGate(NewWorldBeliefSubstrate(e))
	worker := NewSliceBeliefWorker(gate, NativeSliceBeliefProvider(registry, nil))
	sliceOpts, propagateOpts := DefaultSliceSchedule()
	settled := false
	for range 20 {
		_, scored, err := SliceBeliefRound(context.Background(), e, registry, gate, worker, sliceOpts, propagateOpts)
		require.NoError(t, err)
		e.Tick() //nolint:contextcheck // Tick takes no context
		if scored == 0 {
			settled = true
			break
		}
	}
	require.True(t, settled, "the rounds on a cyclic World must settle")
	for _, h := range e.Hosts() {
		assert.Equal(t, []string{"RESOLVES_TO"}, h.CauseEdgeTypes,
			"host %s: its enabler is inside its own slice, also for the edge that a global cut removes", h.Address)
	}
}
