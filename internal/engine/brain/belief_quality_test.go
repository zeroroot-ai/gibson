// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
)

// settledBetWorld holds two hosts and two settled bets: a TRUE bet on the
// first host, a FALSE bet on the second host, and a bet on no known host.
func settledBetWorld() *World {
	w := NewWorld("acme")
	Reduce(w, HostObserved{ScopeID: "s1", Address: "10.0.0.1", OpenPorts: []int{22}})
	Reduce(w, HostObserved{ScopeID: "s1", Address: "10.0.0.2", OpenPorts: []int{443}})
	for id, addr := range map[string]string{"h1": "10.0.0.1", "h2": "10.0.0.2", "h3": "10.9.9.9"} {
		Reduce(w, HypothesisObserved{
			ScopeID: "s1", Claim: "exploitable " + addr, HypothesisID: id,
			References: []ReferencedEntityRef{{Label: "Host", IDProperties: map[string]string{"address": addr}}},
		})
	}
	Reduce(w, BetSettledTrue{HypothesisID: "h1", ScopeID: "s1"})
	Reduce(w, BetSettledFalse{HypothesisID: "h2", ScopeID: "s1"})
	Reduce(w, BetSettledTrue{HypothesisID: "h3", ScopeID: "s1"})
	return w
}

// Each settled bet on a known host gives one case, and the case leaves out
// the exploit that the bet itself demonstrated.
func TestSettledBetCases(t *testing.T) {
	cases := settledBetWorld().SettledBetCases()
	require.Len(t, cases, 2, "the bet on an unknown host gives no case")
	assert.InDelta(t, 1.0, cases[0].Outcome, 0)
	assert.Equal(t, []int{22}, cases[0].Evidence.OpenPorts)
	assert.False(t, cases[0].Evidence.ExploitDemonstrated, "a bet is never scored with its own answer")
	assert.InDelta(t, 0.0, cases[1].Outcome, 0)
}

// A model that says each host is exploitable scores worse on a FALSE bet than
// the base model does on the same bets, and no case means a score of 0.
func TestBrierOnBets(t *testing.T) {
	base, err := beliefvi.DefaultArtifact()
	require.NoError(t, err)
	model, err := beliefvi.NewBeliefModel(base)
	require.NoError(t, err)

	score, n := BrierOnBets(model, nil)
	assert.Zero(t, score)
	assert.Zero(t, n)

	cases := settledBetWorld().SettledBetCases()
	score, n = BrierOnBets(model, cases)
	assert.Equal(t, 2, n)
	assert.Greater(t, score, 0.0)
	assert.Less(t, score, 1.0)

	// A forecast that the model cannot make counts as the worst forecast: a
	// model that says no host is ever reachable cannot score a reachable host.
	impossible, err := beliefvi.DefaultArtifact()
	require.NoError(t, err)
	impossible.CPDs["reachable"] = beliefvi.CPDSpec{Values: [][]float64{{1}, {0}}}
	never, err := beliefvi.NewBeliefModel(impossible)
	require.NoError(t, err)
	worst, n := BrierOnBets(never, []BetCase{{Evidence: BeliefEvidence{Reachable: true, OpenPorts: []int{22}}, Outcome: 0}})
	assert.Equal(t, 1, n)
	assert.InDelta(t, 1.0, worst, 1e-9)
}
