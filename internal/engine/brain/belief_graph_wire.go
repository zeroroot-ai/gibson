// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// belief_graph_wire.go is gibson#275: the belief engine proper. It wires
// DeriveAttackGraph (gibson#286), ExtractBoundedSlice (gibson#287), the
// slice-digest gate (gibson#289) and a SliceBeliefProvider (gibson#288's
// sidecar seam) into the LIVE Engine — the piece every prior belief-engine
// slice explicitly deferred ("not yet wired into a live path").
//
// It runs entirely off the engine's own tick, the same architecture
// WireBelief already uses for the per-host pipeline: a ticker goroutine
// derives the current attack graph from the World (LiveAttackGraph), Checks every node's bounded slice for a digest change,
// and Drains whatever that produced through the provider — never inside
// runSystems, so a slow provider (an HTTP round trip to the sidecar) can never
// stall the ~50ms tick budget (TestWireSliceBelief_RunsOffTheEngineTick).
//
// The per-host pipeline (BeliefSystem/BeliefWorker/WireBelief, belief.go) is
// UNCHANGED and keeps running: it is what actually detects an evidence change
// and produces a host's OWN first-pass belief. This pipeline runs downstream
// of it, refining/propagating through WorldBeliefSubstrate's shared write
// path (BeliefScored, applyBeliefScored's existing staleness check) — the two
// never race, because they write the same field through the same reducer.
//
// The graph comes from LiveAttackGraph (belief_infra_graph.go): the hosts of
// the World plus each relationship of the World that the belief schema marks
// as an enablement edge. With the seed schema only Host bears belief, so an
// edge reaches the attack graph when it links two hosts.

// Default bounds for the live graph-coupled round (ADR-0129: "the bound
// lives in the scope", "propagate... bounded"). Exported so the daemon's
// wiring site states them explicitly rather than relying on a zero value.
const (
	// DefaultSliceMaxDepth bounds how many enablement-edge hops toward a
	// target ExtractBoundedSlice walks.
	DefaultSliceMaxDepth = 3
	// DefaultSliceNodeBudget bounds how many nodes a single slice may retain.
	DefaultSliceNodeBudget = 50
	// DefaultPropagateMaxDepth bounds downstreamAffected's forward walk after
	// a belief changes.
	DefaultPropagateMaxDepth = 2
	// DefaultPropagateNodeBudget bounds how many downstream nodes one change
	// invalidates.
	DefaultPropagateNodeBudget = 50
)

// DefaultSliceSchedule is the sliceOpts/propagateOpts pair WireSliceBelief
// uses when the caller does not need a different bound.
func DefaultSliceSchedule() (sliceOpts, propagateOpts SliceOptions) {
	return SliceOptions{MaxDepth: DefaultSliceMaxDepth, NodeBudget: DefaultSliceNodeBudget},
		SliceOptions{MaxDepth: DefaultPropagateMaxDepth, NodeBudget: DefaultPropagateNodeBudget}
}

// SliceBeliefRound runs one graph-coupled settle pass: derive the current
// attack graph from eng's live hosts, Check every node's bounded slice, tap
// every resulting request, and Drain them through provider. This is exactly
// what WireSliceBelief's ticker calls each interval; it is exported and takes
// gate/worker directly so tests can drive exact rounds deterministically
// (settle()'s tick-drain-tick style in belief_test.go) instead of a real
// timer.
//
// relevance for the deterministic over-budget prune (ADR-0129) is each
// host's OWN attention score (HostSnapshot.Attention — belief.Juicy +
// belief.Exploitable + the surprise boost, attention.go) — reused, not
// recomputed, matching the design
// note on ExtractBoundedSlice's relevance parameter.
func SliceBeliefRound(
	ctx context.Context,
	eng *Engine,
	registry *ontology.BeliefSchemaRegistry,
	gate *SliceGate,
	worker *SliceBeliefWorker,
	sliceOpts SliceOptions,
	propagateOpts SliceOptions,
) (checked, scored int, err error) {
	hosts := eng.Hosts()
	// The uncut graph: each slice breaks its own cycles (gibson#700).
	graph := LiveEnablementGraph(eng, hosts, registry)

	relevance := make(map[string]float64, len(hosts))
	for _, h := range hosts {
		relevance[HostNodeID(h.ID)] = h.Attention
	}

	for _, n := range graph.Nodes {
		req, checkErr := gate.Check(ctx, graph, n.ID, sliceOpts, relevance)
		if checkErr != nil {
			return checked, scored, fmt.Errorf("slice belief round: check %s %s: %w", n.Kind, n.ID, checkErr)
		}
		checked++
		if req != nil {
			worker.Tap(*req)
		}
	}

	scored, _, err = worker.Drain(ctx, graph, propagateOpts)
	if err != nil {
		return checked, scored, fmt.Errorf("slice belief round: drain: %w", err)
	}
	return checked, scored, nil
}

// WireSliceBelief installs the graph-coupled pipeline against eng: a
// WorldBeliefSubstrate-backed SliceGate and a SliceBeliefWorker driving p, run
// on their own ticker (interval <= 0 uses TickInterval, the same convention
// WireBelief uses) bound to ctx. Returns the gate so a caller can inspect or
// drive it directly (tests, or a future admin surface); the live daemon does
// not need to keep it.
func WireSliceBelief(
	ctx context.Context,
	eng *Engine,
	registry *ontology.BeliefSchemaRegistry,
	p SliceBeliefProvider,
	interval time.Duration,
	sliceOpts SliceOptions,
	propagateOpts SliceOptions,
) *SliceGate {
	if interval <= 0 {
		interval = TickInterval
	}
	substrate := NewWorldBeliefSubstrate(eng)
	gate := NewSliceGate(substrate)
	worker := NewSliceBeliefWorker(gate, p)

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_, _, _ = SliceBeliefRound(ctx, eng, registry, gate, worker, sliceOpts, propagateOpts)
				return
			case <-t.C:
				_, _, _ = SliceBeliefRound(ctx, eng, registry, gate, worker, sliceOpts, propagateOpts)
			}
		}
	}()

	return gate
}
