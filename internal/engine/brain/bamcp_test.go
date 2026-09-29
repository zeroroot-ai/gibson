// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// testBAMCPPlanner builds a planner tuned for fast, deterministic tests: far
// fewer simulations than DefaultBAMCPConfig, so voi_planner_test.go's wiring
// tests stay fast, but still enough (and a fixed seed, supplied per-call by
// the caller under test) to exercise every code path a live planner does.
func testBAMCPPlanner(registry *ontology.BeliefSchemaRegistry) *BAMCPPlanner {
	cfg := DefaultBAMCPConfig()
	cfg.Simulations = 5
	return NewBAMCPPlanner(registry, nil, cfg)
}

func bamcpTestRegistry(t *testing.T) *ontology.BeliefSchemaRegistry {
	t.Helper()
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", ontology.SeedBeliefSchemaExtension()))
	return reg
}

// bamcpTestInput builds a small, two-host VoIPlanInput with one enablement
// edge between them (host "1"'s compromise feeds host "2"'s "reachable"),
// mirroring belief_slice_native_test.go's own fixture shape
// (TestGroundAttackGraph_*). Node ids are HostNodeID(h.ID) exactly the way
// VoIWorker.buildInput's own HostsToInfraGraph call produces them
// (belief_world_substrate.go) — a real PlanVoI candidate's RefID must match a
// real graph node id for bamcpOutcome's lookup to ever fire, so this fixture
// deliberately does not use arbitrary host-a/host-b names.
func bamcpTestInput(reg *ontology.BeliefSchemaRegistry) VoIPlanInput {
	graph := AttackGraph{
		Nodes: []AttackGraphNode{
			{InfraNode: InfraNode{ID: HostNodeID(1), Kind: "Host"}, Variables: reg.Variables("Host")},
			{InfraNode: InfraNode{ID: HostNodeID(2), Kind: "Host"}, Variables: reg.Variables("Host")},
		},
		Edges: []InfraEdge{{Type: "RESOLVES_TO", From: HostNodeID(1), To: HostNodeID(2)}},
	}
	return VoIPlanInput{
		Hosts: []HostSnapshot{
			{ID: 1, Address: "10.0.0.1", Belief: Belief{Juicy: 0.6}},
			{ID: 2, Address: "10.0.0.2", Belief: Belief{Juicy: 0.3}},
		},
		Graph:  graph,
		Tenant: "t",
	}
}

// -----------------------------------------------------------------------
// BAMCPSeed
// -----------------------------------------------------------------------

func TestBAMCPSeed_DeterministicForTheSameMissionAndCursor(t *testing.T) {
	assert.Equal(t, BAMCPSeed("m1", 3), BAMCPSeed("m1", 3))
}

func TestBAMCPSeed_DiffersAcrossMissionOrCursor(t *testing.T) {
	base := BAMCPSeed("m1", 3)
	assert.NotEqual(t, base, BAMCPSeed("m2", 3), "different mission should (almost certainly) reseed differently")
	assert.NotEqual(t, base, BAMCPSeed("m1", 4), "different cursor should (almost certainly) reseed differently")
}

// -----------------------------------------------------------------------
// BAMCPPlanner.Plan determinism (this issue's hard acceptance criterion)
// -----------------------------------------------------------------------

// TestBAMCPPlanner_SameSeedReproducesIdenticalRollouts is the direct proof of
// this issue's determinism requirement: two independent Plan calls over the
// same input, with the same seed, must produce byte-for-byte identical
// ranked output. If any code path in bamcp.go ever drew from the package-level
// math/rand/v2 source, or from Go map iteration order, instead of the caller-
// supplied *rand.Rand, this test would flake under `go test -count=10`.
func TestBAMCPPlanner_SameSeedReproducesIdenticalRollouts(t *testing.T) {
	reg := bamcpTestRegistry(t)
	in := bamcpTestInput(reg)
	substrate := newFakeBeliefSubstrate()
	planner := NewBAMCPPlanner(reg, nil, DefaultBAMCPConfig())
	const seed = uint64(0xC0FFEE)

	first, err := planner.Plan(context.Background(), in, substrate, ExactVoIScorer(), 0, seed)
	require.NoError(t, err)

	second, err := planner.Plan(context.Background(), in, substrate, ExactVoIScorer(), 0, seed)
	require.NoError(t, err)

	require.Equal(t, len(first), len(second))
	assert.True(t, reflect.DeepEqual(first, second), "same seed must reproduce identical rollouts:\n got  %+v\nwant %+v", second, first)
}

// TestBAMCPPlanner_DifferentSeedsCanDisagree proves the seed genuinely drives
// the rollouts (not silently ignored): running many distinct seeds over a
// fixture whose two candidates start with different one-step Values, at
// least one seed's BAMCP-refined ranking must differ from another's, since
// each seed Thompson-samples a different model instantiation.
func TestBAMCPPlanner_DifferentSeedsCanDisagree(t *testing.T) {
	reg := bamcpTestRegistry(t)
	in := bamcpTestInput(reg)
	substrate := newFakeBeliefSubstrate()
	cfg := DefaultBAMCPConfig()
	cfg.Simulations = 20
	planner := NewBAMCPPlanner(reg, nil, cfg)

	var values [][]float64
	for seed := uint64(1); seed <= 8; seed++ {
		out, err := planner.Plan(context.Background(), in, substrate, ExactVoIScorer(), 0, seed)
		require.NoError(t, err)
		var vs []float64
		for _, c := range out {
			vs = append(vs, c.Value)
		}
		values = append(values, vs)
	}
	for i := 1; i < len(values); i++ {
		if !reflect.DeepEqual(values[0], values[i]) {
			return // found two seeds that disagree, as expected
		}
	}
	t.Fatalf("every seed from 1..8 produced identical BAMCP values %v; the seed appears to have no effect", values[0])
}

// TestBAMCPPlanner_PreservesCandidateIdentityAndRanksByTopK proves Plan keeps
// PlanVoI's candidate set intact (same RefIDs/Kinds) while only overwriting
// Value, and that topK truncation still applies to the BAMCP-refined ranking
// (ADR-0026 decision 1: "the planner computes the top-k").
func TestBAMCPPlanner_PreservesCandidateIdentityAndRanksByTopK(t *testing.T) {
	reg := bamcpTestRegistry(t)
	in := bamcpTestInput(reg)
	substrate := newFakeBeliefSubstrate()
	planner := testBAMCPPlanner(reg)

	full, err := planner.Plan(context.Background(), in, substrate, ExactVoIScorer(), 0, 42)
	require.NoError(t, err)
	require.Len(t, full, 2)

	refIDs := map[string]bool{}
	for _, c := range full {
		refIDs[c.RefID] = true
	}
	assert.True(t, refIDs[HostNodeID(1)] && refIDs[HostNodeID(2)], "expected both host candidates' identity to survive, got %+v", full)

	top1, err := planner.Plan(context.Background(), in, substrate, ExactVoIScorer(), 1, 42)
	require.NoError(t, err)
	require.Len(t, top1, 1)
	assert.Equal(t, full[0].RefID, top1[0].RefID)
	assert.GreaterOrEqual(t, full[0].Value, full[1].Value, "topK=0 output must already be ranked by descending Value")
}

// TestBAMCPPlanner_EmptyCandidateSetIsANoop proves an empty ambient slice
// (no hosts, no hypotheses) never panics -- PlanVoI itself already returns an
// empty slice for this; Plan must short-circuit before grounding/rollouts.
func TestBAMCPPlanner_EmptyCandidateSetIsANoop(t *testing.T) {
	reg := bamcpTestRegistry(t)
	substrate := newFakeBeliefSubstrate()
	planner := testBAMCPPlanner(reg)

	out, err := planner.Plan(context.Background(), VoIPlanInput{Tenant: "t"}, substrate, ExactVoIScorer(), 0, 1)
	require.NoError(t, err)
	assert.Empty(t, out)
}

// -----------------------------------------------------------------------
// bamcpGround / bamcpTopoOrder / bamcpSampleWorld
// -----------------------------------------------------------------------

// TestBamcpGround_EnablementEdgeKeepsItsType proves bamcpGround, unlike
// groundAttackGraph, preserves the enablement edge's TYPE on the resulting
// cause -- the whole reason this file cannot just reuse
// beliefvi.EnablementCause (belief_slice_native.go's own doc comment).
func TestBamcpGround_EnablementEdgeKeepsItsType(t *testing.T) {
	reg := bamcpTestRegistry(t)
	graph := bamcpTestInput(reg).Graph

	vars := bamcpGround(graph, reg)

	var found bool
	for _, v := range vars {
		for _, c := range v.EdgeCauses {
			if c.EdgeType == "RESOLVES_TO" {
				found = true
			}
		}
	}
	assert.True(t, found, "expected an EdgeCause carrying the RESOLVES_TO edge type, got %+v", vars)
}

// TestBamcpTopoOrder_ParentsComeBeforeChildren proves the returned order is a
// valid topological order over both intra-node and cross-node causes, for
// Host's seed chain (reachable -> exploitable -> juicy) across two enabled
// nodes.
func TestBamcpTopoOrder_ParentsComeBeforeChildren(t *testing.T) {
	reg := bamcpTestRegistry(t)
	graph := bamcpTestInput(reg).Graph
	vars := bamcpGround(graph, reg)

	order := bamcpTopoOrder(vars)
	require.Len(t, order, len(vars))

	index := make(map[string]int, len(order))
	for i, name := range order {
		index[name] = i
	}
	byName := make(map[string]bamcpVar, len(vars))
	for _, v := range vars {
		byName[v.Name] = v
	}
	for _, v := range vars {
		for _, c := range v.IntraCauses {
			assert.Less(t, index[c.Parent], index[v.Name], "%s must come before %s", c.Parent, v.Name)
		}
		for _, c := range v.EdgeCauses {
			assert.Less(t, index[c.Parent], index[v.Name], "%s must come before %s", c.Parent, v.Name)
		}
	}
}

// TestBamcpTopoOrder_IsIndependentOfInputOrder proves the order does not
// depend on the slice order bamcpGround happened to build vars in (it sorts
// internally by name before returning) -- reversing the input must yield the
// exact same output, the determinism discipline this file's doc comment
// requires.
func TestBamcpTopoOrder_IsIndependentOfInputOrder(t *testing.T) {
	reg := bamcpTestRegistry(t)
	graph := bamcpTestInput(reg).Graph
	vars := bamcpGround(graph, reg)

	reversed := make([]bamcpVar, len(vars))
	for i, v := range vars {
		reversed[len(vars)-1-i] = v
	}

	assert.Equal(t, bamcpTopoOrder(vars), bamcpTopoOrder(reversed))
}

// TestBamcpSampleWorld_ThompsonSamplesTheEdgePosterior proves the cross-node
// enablement cause's realized rate tracks the SUPPLIED posterior's mean, not
// the fixed UninformativePriorStrength constant groundAttackGraph's exact
// inference uses -- the whole point of Thompson-sampling per edge TYPE
// (ADR-0037 decision 4) rather than reading one fixed number. A posterior
// concentrated near 1.0 (Beta(200,1), mean ~0.995) must make the downstream host's
// "reachable" ground var realize true far more often than the uninformative
// default (mean 0.5) would, across enough independent seeds.
func TestBamcpSampleWorld_ThompsonSamplesTheEdgePosterior(t *testing.T) {
	reg := bamcpTestRegistry(t)
	graph := bamcpTestInput(reg).Graph
	vars := bamcpGround(graph, reg)
	order := bamcpTopoOrder(vars)

	strongPosteriors := constantEdgePosteriors{p: EdgeStrengthPosterior{Alpha: 200, Beta: 1}}
	weakPosteriors := constantEdgePosteriors{p: EdgeStrengthPosterior{Alpha: 1, Beta: 200}}

	const trials = 300
	var strongTrue, weakTrue int
	for seed := uint64(1); seed <= trials; seed++ {
		rngStrong := rand.New(rand.NewPCG(seed, seed))
		if bamcpSampleWorld(vars, order, strongPosteriors, rngStrong)[HostNodeID(2)+"::reachable"] {
			strongTrue++
		}
		rngWeak := rand.New(rand.NewPCG(seed, seed))
		if bamcpSampleWorld(vars, order, weakPosteriors, rngWeak)[HostNodeID(2)+"::reachable"] {
			weakTrue++
		}
	}

	assert.Greater(t, strongTrue, weakTrue,
		"a near-1.0 edge posterior (%d/%d true) should realize the downstream host's reachable far more often than a near-0.0 one (%d/%d true)",
		strongTrue, trials, weakTrue, trials)
}

// constantEdgePosteriors is a test-only EdgeStrengthPosteriorProvider that
// returns the same posterior for every edge type, so tests can isolate the
// effect of the posterior's shape independent of edge-type lookup.
type constantEdgePosteriors struct{ p EdgeStrengthPosterior }

func (c constantEdgePosteriors) Posterior(string) EdgeStrengthPosterior { return c.p }
