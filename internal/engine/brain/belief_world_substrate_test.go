// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"
)

// TestHostNodeID_RoundTrips proves the string<->uint64 host-id mapping
// InfraNode.ID / NodeRef.ID use for a Host is stable and reversible — the
// live graph construction (HostsToInfraGraph) and WorldBeliefSubstrate must
// agree on it, or a slice-gate write can never find the host it means to.
func TestHostNodeID_RoundTrips(t *testing.T) {
	for _, id := range []uint64{0, 1, 42, 1 << 40} {
		s := HostNodeID(id)
		got, err := ParseHostNodeID(s)
		if err != nil {
			t.Fatalf("ParseHostNodeID(%q): %v", s, err)
		}
		if got != id {
			t.Fatalf("round trip: %d -> %q -> %d", id, s, got)
		}
	}
}

func TestParseHostNodeID_RejectsGarbage(t *testing.T) {
	if _, err := ParseHostNodeID("not-a-number"); err == nil {
		t.Fatalf("ParseHostNodeID accepted a non-numeric id")
	}
}

// TestWorldBeliefSubstrate_BeliefReadsCurrentHostState proves Belief() is a
// live read of the ECS World, not a separate store: it reflects whatever
// belief.go's existing per-host pipeline has already folded.
func TestWorldBeliefSubstrate_BeliefReadsCurrentHostState(t *testing.T) {
	e, bw := beliefEngine(PlaceholderBeliefProvider())
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)

	hosts := e.World.Snapshot()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}

	sub := NewWorldBeliefSubstrate(e)
	nb, ok, err := sub.Belief(context.Background(), NodeRef{Kind: NodeKindHost, ID: HostNodeID(hosts[0].ID)})
	if err != nil {
		t.Fatalf("Belief: %v", err)
	}
	if !ok {
		t.Fatalf("Belief reported ok=false for a real host")
	}
	if nb.Belief != hosts[0].Belief {
		t.Fatalf("Belief = %+v, want the host's own %+v", nb.Belief, hosts[0].Belief)
	}
	if nb.EvidenceDigest != hosts[0].EvidenceDigest {
		t.Fatalf("EvidenceDigest = %q, want %q", nb.EvidenceDigest, hosts[0].EvidenceDigest)
	}
}

func TestWorldBeliefSubstrate_UnknownHostIsNotFound(t *testing.T) {
	e := NewEngine("t")
	sub := NewWorldBeliefSubstrate(e)
	_, ok, err := sub.Belief(context.Background(), NodeRef{Kind: NodeKindHost, ID: HostNodeID(999)})
	if err != nil {
		t.Fatalf("Belief: %v", err)
	}
	if ok {
		t.Fatalf("Belief reported ok=true for a host that was never observed")
	}
}

// TestWorldBeliefSubstrate_BeliefPropagatesAnUnparseableHostID proves an
// unparseable NodeRef.ID surfaces as an error rather than being masked as
// "not found" — a malformed ref is a caller bug, not a legitimately unknown
// host, and nilerr-style swallowing would hide it.
func TestWorldBeliefSubstrate_BeliefPropagatesAnUnparseableHostID(t *testing.T) {
	e := NewEngine("t")
	sub := NewWorldBeliefSubstrate(e)
	_, ok, err := sub.Belief(context.Background(), NodeRef{Kind: NodeKindHost, ID: "not-a-number"})
	if err == nil {
		t.Fatalf("Belief did not surface the unparseable host id as an error")
	}
	if ok {
		t.Fatalf("Belief reported ok=true alongside an error")
	}
}

// TestWorldBeliefSubstrate_NonHostKindIsNotFound documents today's boundary:
// Claim/TechniqueEnvironment (ADR-0029 §3) are not ECS entities yet, so this
// substrate — the ONE backing the live World — has nothing to read for them.
// A different BeliefSubstrate implementation is what those views will need.
func TestWorldBeliefSubstrate_NonHostKindIsNotFound(t *testing.T) {
	e := NewEngine("t")
	sub := NewWorldBeliefSubstrate(e)
	_, ok, err := sub.Belief(context.Background(), NodeRef{Kind: NodeKindClaim, ID: "acme/hyp-1"})
	if err != nil {
		t.Fatalf("Belief: %v", err)
	}
	if ok {
		t.Fatalf("Belief reported ok=true for a non-Host kind this substrate cannot back")
	}
}

func TestWorldBeliefSubstrate_SetBeliefRejectsNonHostKind(t *testing.T) {
	e := NewEngine("t")
	sub := NewWorldBeliefSubstrate(e)
	err := sub.SetBelief(context.Background(), NodeRef{Kind: NodeKindClaim, ID: "acme/hyp-1"}, NodeBelief{})
	if err == nil {
		t.Fatalf("SetBelief accepted a non-Host kind this substrate cannot back")
	}
}

func TestWorldBeliefSubstrate_SetBeliefRejectsAnUnparseableHostID(t *testing.T) {
	e := NewEngine("t")
	sub := NewWorldBeliefSubstrate(e)
	err := sub.SetBelief(context.Background(), NodeRef{Kind: NodeKindHost, ID: "not-a-number"}, NodeBelief{})
	if err == nil {
		t.Fatalf("SetBelief accepted an unparseable host id")
	}
}

// TestWorldBeliefSubstrate_SetBeliefAppliesThroughTheExistingReducer proves
// SetBelief does not mutate the World directly: it Submits a BeliefScored
// event (belief.go, unchanged reducer) that only takes effect once the engine
// ticks, and it is subject to the SAME staleness check applyBeliefScored
// already enforces — the graph-coupled pipeline and the per-host pipeline
// share one write path into Host.Belief, so they cannot fight over it.
func TestWorldBeliefSubstrate_SetBeliefAppliesThroughTheExistingReducer(t *testing.T) {
	e, bw := beliefEngine(PlaceholderBeliefProvider())
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)
	hostID := e.World.Snapshot()[0].ID
	sub := NewWorldBeliefSubstrate(e)
	ctx := context.Background()

	current, ok, err := sub.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)})
	if err != nil || !ok {
		t.Fatalf("setup Belief: nb=%+v ok=%v err=%v", current, ok, err)
	}

	refined := NodeBelief{
		Belief:         Belief{Juicy: 0.99, Exploitable: 0.99, Reachable: 1, Model: "graph-refined"},
		EvidenceDigest: current.EvidenceDigest, // same evidence, refined inference — not stale
	}
	if err := sub.SetBelief(ctx, NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)}, refined); err != nil {
		t.Fatalf("SetBelief: %v", err)
	}

	// Not applied yet: SetBelief only Submits, the reducer runs on Tick.
	before, _, _ := sub.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)})
	if before.Belief.Model == "graph-refined" {
		t.Fatalf("SetBelief mutated the World before a Tick folded it")
	}

	e.Tick()

	after, _, err := sub.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)})
	if err != nil {
		t.Fatalf("Belief after tick: %v", err)
	}
	if after.Belief.Model != "graph-refined" {
		t.Fatalf("Belief after tick = %+v, want the graph-refined score applied", after.Belief)
	}
}

// TestWorldBeliefSubstrate_StaleEvidenceDigestIsDropped proves the shared
// write path's staleness guard still holds for a graph-coupled write: if the
// host's evidence moved on since the digest the caller read, the write is
// silently dropped (the same behavior a stale per-host BeliefScored gets).
func TestWorldBeliefSubstrate_StaleEvidenceDigestIsDropped(t *testing.T) {
	e, bw := beliefEngine(PlaceholderBeliefProvider())
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	settle(e, bw, 1)
	hostID := e.World.Snapshot()[0].ID
	sub := NewWorldBeliefSubstrate(e)
	ctx := context.Background()

	stale := NodeBelief{
		Belief:         Belief{Juicy: 0.5, Model: "stale-write"},
		EvidenceDigest: "digest-of-evidence-the-host-has-moved-past",
	}
	if err := sub.SetBelief(ctx, NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)}, stale); err != nil {
		t.Fatalf("SetBelief: %v", err)
	}
	e.Tick()

	got, _, _ := sub.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: HostNodeID(hostID)})
	if got.Belief.Model == "stale-write" {
		t.Fatalf("a stale-digest write was applied: %+v", got.Belief)
	}
}

// TestHostsToInfraGraph_MapsEveryHostToAHostKindNode proves the live-graph
// construction uses the SAME id/kind convention WorldBeliefSubstrate reads
// and writes, end to end.
func TestHostsToInfraGraph_MapsEveryHostToAHostKindNode(t *testing.T) {
	hosts := []HostSnapshot{{ID: 1}, {ID: 42}}
	nodes := HostsToInfraGraph(hosts)
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}
	want := map[string]bool{HostNodeID(1): true, HostNodeID(42): true}
	for _, n := range nodes {
		if n.Kind != "Host" {
			t.Errorf("node %+v has Kind %q, want Host", n, n.Kind)
		}
		if !want[n.ID] {
			t.Errorf("unexpected node id %q", n.ID)
		}
		delete(want, n.ID)
	}
	if len(want) != 0 {
		t.Errorf("missing node ids: %v", want)
	}
}
