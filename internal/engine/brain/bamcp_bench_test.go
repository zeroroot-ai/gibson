// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// bamcpBenchInput builds the planning input of one decision for a mission of
// a realistic size: a chain of hosts, each one enabling the next, plus a few
// open hypotheses.
func bamcpBenchInput(reg *ontology.BeliefSchemaRegistry, hosts, hypotheses int) VoIPlanInput {
	in := VoIPlanInput{Tenant: "t"}
	for i := 1; i <= hosts; i++ {
		id := uint64(i) //nolint:gosec // G115: a small loop counter
		in.Hosts = append(in.Hosts, HostSnapshot{
			ID: id, Address: fmt.Sprintf("10.0.0.%d", i),
			Belief: Belief{Juicy: 0.2 + 0.6*float64(i%5)/5},
		})
		in.Graph.Nodes = append(in.Graph.Nodes, AttackGraphNode{
			InfraNode: InfraNode{ID: HostNodeID(id), Kind: "Host"}, Variables: reg.Variables("Host"),
		})
		if i > 1 {
			in.Graph.Edges = append(in.Graph.Edges, InfraEdge{
				Type: "RESOLVES_TO", From: HostNodeID(id - 1), To: HostNodeID(id),
			})
		}
	}
	for i := 1; i <= hypotheses; i++ {
		in.Hypotheses = append(in.Hypotheses, HypothesisSnapshot{
			ID: uint64(1000 + i), ScopeID: "s", Claim: fmt.Sprintf("claim %d", i), //nolint:gosec // G115: a small loop counter
		})
	}
	return in
}

// BenchmarkBAMCPPlan records the planning time for one decision with the
// default configuration: 12 hosts and 4 hypotheses, top 10.
func BenchmarkBAMCPPlan(b *testing.B) {
	reg := ontology.NewBeliefSchemaRegistry()
	if err := reg.RegisterExtension("core/belief-schema", ontology.SeedBeliefSchemaExtension()); err != nil {
		b.Fatal(err)
	}
	in := bamcpBenchInput(reg, 12, 4)
	substrate := newFakeBeliefSubstrate()
	planner := NewBAMCPPlanner(reg, nil, DefaultBAMCPConfig())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := planner.Plan(context.Background(), in, substrate, ExactVoIScorer(), DefaultVoITopK, 0xC0FFEE); err != nil {
			b.Fatal(err)
		}
	}
}
