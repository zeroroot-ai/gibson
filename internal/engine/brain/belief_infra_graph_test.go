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

// hostIDAt returns the stable id of the host at address.
func hostIDAt(t *testing.T, e *Engine, address string) uint64 {
	t.Helper()
	for _, h := range e.Hosts() {
		if h.Address == address {
			return h.ID
		}
	}
	t.Fatalf("no host at %s", address)
	return 0
}

// linkHosts records an enablement relationship from one host to a second
// host, the way an agent reports it: an entity sighting of the first host
// with one edge to the second (ADR-0107).
func linkHosts(e *Engine, from, to uint64) {
	e.Submit(EntityObserved{
		Label: "Host", Key: HostNodeID(from), ScopeID: "s",
		Edges: []EntityEdge{{Type: "RESOLVES_TO", TargetLabel: "Host", TargetKey: HostNodeID(to)}},
	})
}

func hasEdge(edges []InfraEdge, edgeType, from, to string) bool {
	return slices.Contains(edges, InfraEdge{Type: edgeType, From: from, To: to})
}

// TestInfraGraph_HoldsTheRelationshipsOfTheWorld proves that the infra graph
// carries each relationship kind of the World, with the endpoint ids that the
// belief substrate uses for a Host.
func TestInfraGraph_HoldsTheRelationshipsOfTheWorld(t *testing.T) {
	e := NewEngine("t", &memTimelineStore{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22},
		Services: map[int]ServiceInfo{22: {Name: "ssh"}}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{80}})
	e.Submit(DomainObserved{ScopeID: "s", Name: "example.com"})
	e.Submit(SubdomainObserved{ScopeID: "s", FQDN: "api.example.com", Domain: "example.com", Addresses: []string{"10.0.0.5"}})
	e.Submit(FindingRaised{ID: "f1", Title: "weak ssh", ScopeID: "s", Address: "10.0.0.5", Severity: "high"})
	e.Submit(AgentRunObserved{RunID: "run-parent", AgentName: "a", ScopeID: "s"})
	e.Submit(AgentRunObserved{RunID: "run-child", ParentRunID: "run-parent", AgentName: "b", ScopeID: "s"})
	e.Submit(LlmCallObserved{CallID: "call-1", RunID: "run-child", Model: "m"})
	e.Tick()
	a, b := hostIDAt(t, e, "10.0.0.5"), hostIDAt(t, e, "10.0.0.6")
	linkHosts(e, a, b)
	e.Submit(EntityObserved{Label: "Deployment", Key: "prod/api", ScopeID: "s",
		Edges: []EntityEdge{{Type: "EXPOSES", TargetLabel: "Host", TargetKey: HostNodeID(a)}}})
	e.Tick()

	nodes, edges := e.InfraGraph()
	hostA, hostB := HostNodeID(a), HostNodeID(b)

	kinds := map[string]string{}
	for _, n := range nodes {
		_, dup := kinds[n.ID]
		require.False(t, dup, "node %q is in the graph two times", n.ID)
		kinds[n.ID] = n.Kind
	}
	assert.Equal(t, "Host", kinds[hostA])
	assert.Equal(t, "Host", kinds[hostB])
	assert.Equal(t, "Deployment", kinds["Deployment/prod/api"])
	assert.Equal(t, "Finding", kinds["Finding/f1"])
	assert.Equal(t, "AgentRun", kinds["AgentRun/run-child"])
	assert.Equal(t, "LlmCall", kinds["LlmCall/call-1"])
	hostNodes := 0
	for _, kind := range kinds {
		if kind == "Host" {
			hostNodes++
		}
	}
	assert.Equal(t, 2, hostNodes, "an entity with the label Host adds no second node")

	assert.True(t, hasEdge(edges, "RESOLVES_TO", hostA, hostB), "the host link: %+v", edges)
	assert.True(t, hasEdge(edges, "EXPOSES", "Deployment/prod/api", hostA))
	assert.True(t, hasEdge(edges, "AFFECTS", "Finding/f1", hostA))
	assert.True(t, hasEdge(edges, "DELEGATED_TO", "AgentRun/run-parent", "AgentRun/run-child"))
	assert.True(t, hasEdge(edges, "ISSUED", "AgentRun/run-child", "LlmCall/call-1"))
	assert.True(t, hasEdge(edges, "HAS_PORT", hostA, "Port/"+hostA+"/22"))
	assert.True(t, hasEdge(edges, "RUNS_SERVICE", "Port/"+hostA+"/22", "Service/"+hostA+"/22"))

	var resolves, hasSubdomain int
	for _, edge := range edges {
		switch {
		case edge.Type == "RESOLVES_TO" && edge.To == hostA && kinds[edge.From] == "Subdomain":
			resolves++
		case edge.Type == "HAS_SUBDOMAIN" && kinds[edge.From] == "Domain" && kinds[edge.To] == "Subdomain":
			hasSubdomain++
		}
	}
	assert.Equal(t, 1, resolves, "the subdomain resolves to host A")
	assert.Equal(t, 1, hasSubdomain)

	// The same World gives the same graph, in the same order.
	nodes2, edges2 := e.InfraGraph()
	assert.Equal(t, nodes, nodes2)
	assert.Equal(t, edges, edges2)
}

// TestLiveAttackGraph_KeepsTheEdgeBetweenTwoHosts proves the derivation that
// the two live call sites share: the link of two hosts is an edge of the attack
// graph, and a host outside the bound takes its edges with it.
func TestLiveAttackGraph_KeepsTheEdgeBetweenTwoHosts(t *testing.T) {
	e := NewEngine("t", &memTimelineStore{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{80}})
	e.Tick()
	a, b := hostIDAt(t, e, "10.0.0.5"), hostIDAt(t, e, "10.0.0.6")
	linkHosts(e, a, b)
	e.Tick()
	registry := liveBeliefRegistry(t)

	graph := LiveAttackGraph(e, e.Hosts(), registry)
	require.Len(t, graph.Nodes, 2)
	require.Equal(t, []InfraEdge{{Type: "RESOLVES_TO", From: HostNodeID(a), To: HostNodeID(b)}}, graph.Edges)

	onlyB := LiveAttackGraph(e, []HostSnapshot{{ID: b}}, registry)
	require.Len(t, onlyB.Nodes, 1)
	require.Empty(t, onlyB.Edges, "host A is outside the bound, so its edge is gone")
}

// TestSliceBeliefRound_ALinkedHostChangesTheBeliefOfTheOtherHost is the proof
// of gibson#697 for the belief engine. Two hosts get a belief each. Then the
// World learns that host A enables host B. The next round gives host B a
// different belief, and names the edge type as its cause. Then new evidence
// arrives on host A, and the round scores host B again, because the slice of
// host B now holds host A.
//
// The test fails when SliceBeliefRound derives the graph with no edges: host B
// then keeps its first belief and new evidence on host A does not reach it.
func TestSliceBeliefRound_ALinkedHostChangesTheBeliefOfTheOtherHost(t *testing.T) {
	e, bw := beliefEngine(deterministicBelief{})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{80}})
	settle(e, bw, 1)
	a, b := hostIDAt(t, e, "10.0.0.5"), hostIDAt(t, e, "10.0.0.6")

	registry := liveBeliefRegistry(t)
	substrate := NewWorldBeliefSubstrate(e)
	gate := NewSliceGate(substrate)
	worker := NewSliceBeliefWorker(gate, NativeSliceBeliefProvider(registry, nil))
	ctx := context.Background()
	sliceOpts, propagateOpts := DefaultSliceSchedule()
	round := func() int {
		t.Helper()
		_, scored, err := SliceBeliefRound(ctx, e, registry, gate, worker, sliceOpts, propagateOpts)
		require.NoError(t, err)
		e.Tick() //nolint:contextcheck // Tick takes no context
		return scored
	}
	settleRounds := func() {
		t.Helper()
		for range 10 {
			if round() == 0 {
				return
			}
		}
		t.Fatal("the slice belief rounds did not settle")
	}
	beliefOf := func(id uint64) HostSnapshot {
		t.Helper()
		for _, h := range e.Hosts() {
			if h.ID == id {
				return h
			}
		}
		t.Fatalf("no host %d", id)
		return HostSnapshot{}
	}

	settleRounds()
	alone := beliefOf(b)
	require.Empty(t, alone.CauseEdgeTypes, "host B has no cause before the link")

	linkHosts(e, a, b)
	e.Tick()
	settleRounds()
	linked := beliefOf(b)
	assert.Equal(t, []string{"RESOLVES_TO"}, linked.CauseEdgeTypes, "the edge from host A is a cause of host B")
	assert.Greater(t, linked.Belief.Reachable, alone.Belief.Reachable,
		"host A enables host B, so host B is more reachable than it was alone")
	assert.Empty(t, beliefOf(a).CauseEdgeTypes, "the edge points at host B, so host A has no cause")

	// New evidence on host A: a second open port. The per-host pipeline gives
	// host A a new belief, and the slice of host B holds host A.
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 443}})
	settle(e, bw, 1)
	require.Positive(t, round(), "new evidence on host A must score the slice of host B again")
}

// TestVoIWorker_BuildInputCarriesTheEdgesOfTheWorld is the proof of gibson#697
// for the planner. The test fails when buildInput derives the graph with no
// edges: the connectivity of each candidate is then zero.
func TestVoIWorker_BuildInputCarriesTheEdgesOfTheWorld(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)
	e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.6", OpenPorts: []int{80}})
	e.Tick()
	a, b := hostIDAt(t, e, "10.0.0.5"), hostIDAt(t, e, "10.0.0.6")
	linkHosts(e, a, b)
	e.Tick()

	in := w.buildInput("m1", e.DomainPacks(), registry)
	require.Equal(t, []InfraEdge{{Type: "RESOLVES_TO", From: HostNodeID(a), To: HostNodeID(b)}}, in.Graph.Edges)

	candidates, err := PlanVoI(context.Background(), in, substrate, ExactVoIScorer(), 0)
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	degree := attackGraphDegree(in.Graph)
	assert.Equal(t, 1, degree[HostNodeID(a)])
	assert.Equal(t, 1, degree[HostNodeID(b)])
}
