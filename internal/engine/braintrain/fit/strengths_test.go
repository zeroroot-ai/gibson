// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

func hostSchema(t *testing.T) ontology.NodeBeliefSchema {
	t.Helper()
	for _, n := range ontology.SeedBeliefSchemaExtension().Nodes {
		if n.NodeType == ontology.HostNodeType {
			return n
		}
	}
	t.Fatal("the seed has no Host schema")
	return ontology.NodeBeliefSchema{}
}

func mean(p BetaPosterior) float64 { return p.Alpha / (p.Alpha + p.Beta) }

// The acceptance test of gibson#720: fitted outcomes move an in-node strength
// and a leak away from 0.5.
func TestNodeStrengths_OutcomesMoveTheStrengths(t *testing.T) {
	rows := []Row{
		// reachable hosts: 4 of 5 are exploitable.
		{"reachable": true, "exploitable": true},
		{"reachable": true, "exploitable": true},
		{"reachable": true, "exploitable": true},
		{"reachable": true, "exploitable": true},
		{"reachable": true},
		// unreachable hosts: none is exploitable.
		{}, {}, {},
	}
	inNode, leaks := NodeStrengths(rows, hostSchema(t))

	s := inNode[InNodeKey("Host", "exploitable", "reachable")]
	assert.Equal(t, BetaPosterior{Alpha: 5, Beta: 2}, s)
	assert.Greater(t, mean(s), 0.5)

	l := leaks[LeakKey("Host", "exploitable")]
	assert.Equal(t, BetaPosterior{Alpha: 1, Beta: 4}, l)
	assert.Less(t, mean(l), 0.5)

	// reachable has no in-node parent: its leak counts each row.
	assert.Equal(t, BetaPosterior{Alpha: 6, Beta: 4}, leaks[LeakKey("Host", "reachable")])
	// juicy depends on exploitable: no row is juicy.
	assert.Equal(t, BetaPosterior{Alpha: 1, Beta: 5}, inNode[InNodeKey("Host", "juicy", "exploitable")])
}

// With no row each strength is the uninformative prior, mean 0.5.
func TestNodeStrengths_NoRowIsThePrior(t *testing.T) {
	inNode, leaks := NodeStrengths(nil, hostSchema(t))
	require.NotEmpty(t, inNode)
	require.NotEmpty(t, leaks)
	for k, p := range inNode {
		assert.InDelta(t, 0.5, mean(p), 1e-12, k)
	}
	for k, p := range leaks {
		assert.InDelta(t, 0.5, mean(p), 1e-12, k)
	}
}

// A row with two active parents teaches no single-parent strength and no leak.
func TestNodeStrengths_TwoActiveParentsTeachNothing(t *testing.T) {
	schema := ontology.NodeBeliefSchema{NodeType: "X", Variables: []ontology.BeliefVariable{
		{Name: "a"}, {Name: "b"}, {Name: "c", DependsOn: []string{"a", "b"}},
	}}
	inNode, leaks := NodeStrengths([]Row{{"a": true, "b": true, "c": true}}, schema)
	assert.Equal(t, BetaPosterior{Alpha: 1, Beta: 1}, inNode[InNodeKey("X", "c", "a")])
	assert.Equal(t, BetaPosterior{Alpha: 1, Beta: 1}, leaks[LeakKey("X", "c")])
}

// Validate refuses a bad in-node strength or leak.
func TestValidate_RefusesABadNodeStrength(t *testing.T) {
	a := &EdgePosteriorArtifact{Version: "v1", InNode: map[string]BetaPosterior{"Host/x<-y": {Alpha: 0, Beta: 1}}}
	require.ErrorContains(t, a.Validate(), "in-node strength")
	a = &EdgePosteriorArtifact{Version: "v1", Leaks: map[string]BetaPosterior{"Host/x": {Alpha: 1, Beta: -1}}}
	require.ErrorContains(t, a.Validate(), "leak")
}
