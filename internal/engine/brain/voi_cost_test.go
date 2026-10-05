// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// voi_cost_test.go proves the two real costs of gibson#695: the resource cost
// scales with the budget that the mission has left, and the risk cost is
// higher for a candidate with the destructive mark.

func TestVoIBudget_SpentFraction(t *testing.T) {
	cases := []struct {
		name   string
		budget VoIBudget
		want   float64
	}{
		{"no limit", VoIBudget{Executions: 50, TokensUsed: 9000}, 0},
		{"full budget", VoIBudget{MaxExecutions: 10, MaxTokens: 1000}, 0},
		{"executions only", VoIBudget{MaxExecutions: 10, Executions: 4}, 0.4},
		{"tokens only", VoIBudget{MaxTokens: 1000, TokensUsed: 250}, 0.25},
		{"the larger dimension wins", VoIBudget{MaxExecutions: 10, Executions: 2, MaxTokens: 1000, TokensUsed: 900}, 0.9},
		{"past the limit is fully spent", VoIBudget{MaxExecutions: 10, Executions: 15}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.InDelta(t, tc.want, tc.budget.SpentFraction(), 1e-12)
		})
	}
}

func TestVoiCosts_ResourceCostScalesWithTheBudgetLeft(t *testing.T) {
	full, risk := voiCosts(VoICandidateHypothesis, 0, false)
	assert.InDelta(t, voiHypothesisTestResourceCost, full, 1e-12)
	assert.InDelta(t, voiHypothesisTestRiskCost, risk, 1e-12)

	half, riskHalf := voiCosts(VoICandidateHypothesis, 0.5, false)
	assert.InDelta(t, 2*voiHypothesisTestResourceCost, half, 1e-12, "half of the budget left doubles the resource cost")
	assert.InDelta(t, risk, riskHalf, 1e-12, "the budget does not change the risk cost")

	// The spent part is capped, so the cost stays finite at an empty budget.
	empty, _ := voiCosts(VoICandidateEvidence, 1, false)
	assert.InDelta(t, voiEvidenceMoveResourceCost/(1-voiMaxBudgetSpent), empty, 1e-9)
}

func TestVoiCosts_ADestructiveCandidateHasAHigherRiskCost(t *testing.T) {
	resource, risk := voiCosts(VoICandidateHypothesis, 0, false)
	resourceD, riskD := voiCosts(VoICandidateHypothesis, 0, true)
	assert.InDelta(t, resource, resourceD, 1e-12, "the destructive mark does not change the resource cost")
	assert.InDelta(t, voiDestructiveRiskMultiplier*risk, riskD, 1e-12)
	assert.Greater(t, riskD, risk)
}

// costRankInput holds two hypotheses. "safe" has no destructive mark and
// names two entities. "boom" has the destructive mark and names three, so it
// gives more information at a higher risk.
func costRankInput(budget VoIBudget) VoIPlanInput {
	refs := func(n int) []ReferencedEntityRef {
		out := make([]ReferencedEntityRef, n)
		for i := range out {
			out[i] = ReferencedEntityRef{Label: "Host"}
		}
		return out
	}
	return VoIPlanInput{
		Tenant: "t",
		Hypotheses: []HypothesisSnapshot{
			{ID: 1, ScopeID: "s", Claim: "safe", References: refs(1)},
			{ID: 2, ScopeID: "s", Claim: "boom", Technique: "t_boom", References: refs(2)},
		},
		Budget:                budget,
		DestructiveTechniques: map[string]bool{"t_boom": true},
	}
}

// TestPlanVoI_TwoBudgetsRankTheSameCandidatesDifferently is the acceptance
// test of gibson#695: the same two candidates, two missions, two ranks.
//
// With a full budget the risk cost decides, and the hypothesis with no
// destructive mark is first. With one tenth of the budget left the resource
// cost is the larger part of each total, the risk is a smaller part of the
// difference, and the hypothesis that gives more information is first.
func TestPlanVoI_TwoBudgetsRankTheSameCandidatesDifferently(t *testing.T) {
	substrate := newFakeBeliefSubstrate()

	full, err := PlanVoI(context.Background(), costRankInput(VoIBudget{MaxExecutions: 100}), substrate, ExactVoIScorer(), 0)
	require.NoError(t, err)
	low, err := PlanVoI(context.Background(), costRankInput(VoIBudget{MaxExecutions: 100, Executions: 90}), substrate, ExactVoIScorer(), 0)
	require.NoError(t, err)
	require.Len(t, full, 2)
	require.Len(t, low, 2)

	assert.Equal(t, "1", full[0].RefID, "full budget: the hypothesis with no destructive mark is first: %+v", full)
	assert.Equal(t, "2", low[0].RefID, "low budget: the hypothesis with more information is first: %+v", low)

	// The plan records the costs that made the rank.
	byRef := func(cs []VoICandidate, ref string) VoICandidate {
		for _, c := range cs {
			if c.RefID == ref {
				return c
			}
		}
		t.Fatalf("no candidate %q in %+v", ref, cs)
		return VoICandidate{}
	}
	assert.InDelta(t, voiHypothesisTestResourceCost, byRef(full, "1").ResourceCost, 1e-9)
	assert.InDelta(t, 10*voiHypothesisTestResourceCost, byRef(low, "1").ResourceCost, 1e-9)
	assert.True(t, byRef(full, "2").Destructive)
	assert.False(t, byRef(full, "1").Destructive)
	assert.InDelta(t, voiDestructiveRiskMultiplier*voiHypothesisTestRiskCost, byRef(full, "2").RiskCost, 1e-9)
}

func TestDestructiveTechniques_ReadsTheMarkOfEachEnabledPack(t *testing.T) {
	assert.Nil(t, destructiveTechniques(nil))

	got := destructiveTechniques([]DomainPackSnapshot{
		{
			Name:                     "web",
			Predicates:               map[string]string{"t_read": "true", "t_delete": "true"},
			NonDestructivePredicates: []string{"t_read"},
		},
		{
			// A second pack binds t_read with no non-destructive statement.
			// One destructive mark is sufficient.
			Name:       "legacy",
			Predicates: map[string]string{"t_read": "true"},
		},
	})
	assert.Equal(t, map[string]bool{"t_delete": true, "t_read": true}, got)

	onlySafe := destructiveTechniques([]DomainPackSnapshot{{
		Name:                     "web",
		Predicates:               map[string]string{"t_read": "true"},
		NonDestructivePredicates: []string{"t_read"},
	}})
	assert.Empty(t, onlySafe)
}

// TestVoIWorker_CostsComeFromTheMissionAndThePacks proves the live path: the
// worker reads the budget of each mission and the destructive mark of each
// technique from the World, and the plan records the costs. Two missions of
// one tenant see the same hypotheses. Only their budgets differ.
func TestVoIWorker_CostsComeFromTheMissionAndThePacks(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)

	e.Submit(DomainPackEnabled{
		Name: "web", Version: 1,
		Predicates:               map[string]string{"t_read": "true", "t_delete": "true"},
		NonDestructivePredicates: []string{"t_read"},
	})
	e.Submit(MissionProjected{ID: "m-full", Goal: "find a path", Budget: Budget{MaxTokens: 1000}})
	e.Submit(MissionProjected{ID: "m-low", Goal: "find a path", Budget: Budget{MaxTokens: 1000}})
	e.Submit(TokenUsed{MissionID: "m-low", Tokens: 750})
	e.Submit(HypothesisObserved{ScopeID: "s", Claim: "read works", Proposer: "a", Technique: "t_read"})
	e.Submit(HypothesisObserved{ScopeID: "s", Claim: "delete works", Proposer: "a", Technique: "t_delete"})

	voiSettle(e, w, 1)

	assert.Equal(t, VoIBudget{MaxTokens: 1000}, w.missionBudget("m-full"))
	assert.Equal(t, VoIBudget{MaxTokens: 1000, TokensUsed: 750}, w.missionBudget("m-low"))
	assert.Equal(t, VoIBudget{}, w.missionBudget("no-such-mission"))

	plans := map[string]VoIPlanSnapshot{}
	for _, p := range e.VoIPlanSnapshot() {
		plans[p.MissionID] = p
	}
	require.Len(t, plans["m-full"].Candidates, 2)
	require.Len(t, plans["m-low"].Candidates, 2)

	for _, c := range plans["m-full"].Candidates {
		assert.InDelta(t, voiHypothesisTestResourceCost, c.ResourceCost, 1e-9, "m-full has its full budget: %+v", c)
	}
	for _, c := range plans["m-low"].Candidates {
		assert.InDelta(t, 4*voiHypothesisTestResourceCost, c.ResourceCost, 1e-9, "m-low has one quarter left: %+v", c)
	}
	for _, c := range plans["m-full"].Candidates {
		switch c.Technique {
		case "t_delete":
			assert.True(t, c.Destructive)
			assert.InDelta(t, voiDestructiveRiskMultiplier*voiHypothesisTestRiskCost, c.RiskCost, 1e-9)
		case "t_read":
			assert.False(t, c.Destructive)
			assert.InDelta(t, voiHypothesisTestRiskCost, c.RiskCost, 1e-9)
		default:
			t.Fatalf("unexpected candidate %+v", c)
		}
	}
}

// TestVoIWorker_ExecutionsCountTheDispatchAttempts proves that the executions
// dimension of the budget counts what BudgetSystem counts: the dispatch
// attempts of the work of the mission.
func TestVoIWorker_ExecutionsCountTheDispatchAttempts(t *testing.T) {
	substrate := newFakeBeliefSubstrate()
	registry := liveBeliefRegistry(t)
	e, w := voiEngine(substrate, registry, ExactVoIScorer(), DefaultVoITopK)

	e.Submit(MissionProjected{ID: "m1", Goal: "g", Budget: Budget{MaxExecutions: 4}})
	e.Submit(WorkDispatched{ID: "m1-w1", MissionID: "m1", ItemKind: "tool", Target: "nmap"})
	e.Submit(WorkDispatched{ID: "m1-w2", MissionID: "m1", ItemKind: "tool", Target: "nmap"})
	e.Submit(WorkDispatched{ID: "m2-w1", MissionID: "m2", ItemKind: "tool", Target: "nmap"})
	e.Tick()

	got := w.missionBudget("m1")
	assert.Equal(t, 4, got.MaxExecutions)
	assert.Equal(t, 2, got.Executions, "only the work of m1 counts")
	assert.InDelta(t, 0.5, got.SpentFraction(), 1e-12)
}
