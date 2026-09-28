// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// TestApplyNodeBeliefSet_RecordsANewNode proves a NodeBeliefSet on a node with
// no prior record creates one, readable back via NodeBeliefSnapshot.
func TestApplyNodeBeliefSet_RecordsANewNode(t *testing.T) {
	w := NewWorld("t")
	ref := NodeRef{Kind: NodeKindClaim, ID: "acme/7"}
	Reduce(w, NodeBeliefSet{Ref: ref, Belief: Belief{Exploitable: 0.8, Model: "bet:v1"}, EvidenceDigest: "d1"})

	got := w.NodeBeliefSnapshot()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	if got[0].Ref != ref || got[0].Belief.Exploitable != 0.8 || got[0].EvidenceDigest != "d1" {
		t.Fatalf("record = %+v, want Ref=%+v Exploitable=0.8 EvidenceDigest=d1", got[0], ref)
	}
}

// TestApplyNodeBeliefSet_EmptyRefIsANoOp mirrors every other reducer's
// empty-identity guard (e.g. applyBetSettledTrue's empty HypothesisID): a
// node with no addressable identity records nothing.
func TestApplyNodeBeliefSet_EmptyRefIsANoOp(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindClaim, ID: ""}, Belief: Belief{Exploitable: 0.5}})
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: "", ID: "x"}, Belief: Belief{Exploitable: 0.5}})

	if got := w.NodeBeliefSnapshot(); len(got) != 0 {
		t.Fatalf("got %d records, want 0 for an unaddressable ref: %+v", len(got), got)
	}
}

// TestApplyNodeBeliefSet_OverwritesInFull proves a belief is never blended or
// averaged across writes (ADR-0005 §2: exact, deterministic) — the second
// write replaces the first outright, matching BeliefSubstrate.SetBelief's own
// documented contract.
func TestApplyNodeBeliefSet_OverwritesInFull(t *testing.T) {
	w := NewWorld("t")
	ref := NodeRef{Kind: NodeKindTechniqueEnvironment, ID: "ssh_bruteforce@linux"}
	Reduce(w, NodeBeliefSet{Ref: ref, Belief: Belief{Exploitable: 0.3}, EvidenceDigest: "d1"})
	Reduce(w, NodeBeliefSet{Ref: ref, Belief: Belief{Exploitable: 0.9}, EvidenceDigest: "d2"})

	got := w.NodeBeliefSnapshot()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (same ref, overwritten not duplicated): %+v", len(got), got)
	}
	if got[0].Belief.Exploitable != 0.9 || got[0].EvidenceDigest != "d2" {
		t.Fatalf("record = %+v, want the SECOND write's values (0.9, d2), not blended", got[0])
	}
}

// TestApplyNodeBeliefSet_DifferentKindsSameIDStayDistinct proves NodeRef's own
// documented identity contract holds through this store too: two refs of
// different Kind never collide even when their ID strings are equal.
func TestApplyNodeBeliefSet_DifferentKindsSameIDStayDistinct(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindClaim, ID: "7"}, Belief: Belief{Exploitable: 0.2}})
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindTechniqueEnvironment, ID: "7"}, Belief: Belief{Exploitable: 0.6}})

	got := w.NodeBeliefSnapshot()
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 (distinct kinds, same id string): %+v", len(got), got)
	}
}

// TestNodeBeliefSnapshot_DeterministicOrder proves the snapshot is ordered
// (Kind, then ID) regardless of write order — the same total-order discipline
// every other Snapshot accessor in this package holds to.
func TestNodeBeliefSnapshot_DeterministicOrder(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindTechniqueEnvironment, ID: "b"}, Belief: Belief{}})
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindClaim, ID: "z"}, Belief: Belief{}})
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindClaim, ID: "a"}, Belief: Belief{}})

	got := w.NodeBeliefSnapshot()
	want := []NodeRef{
		{Kind: NodeKindClaim, ID: "a"},
		{Kind: NodeKindClaim, ID: "z"},
		{Kind: NodeKindTechniqueEnvironment, ID: "b"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Ref != w {
			t.Fatalf("order[%d] = %+v, want %+v", i, got[i].Ref, w)
		}
	}
}

// TestNodeBeliefSet_ReplayReproducesExactly proves replay folds this event
// identically — the same World==fold(Timeline) discipline every other
// belief-engine event in this package holds to.
func TestNodeBeliefSet_ReplayReproducesExactly(t *testing.T) {
	e := NewEngine("t")
	e.Submit(NodeBeliefSet{Ref: NodeRef{Kind: NodeKindClaim, ID: "acme/1"}, Belief: Belief{Exploitable: 0.42}, EvidenceDigest: "d"})
	e.Tick()

	replayed := Replay("t", e.Timeline)
	if !reflect.DeepEqual(replayed.NodeBeliefSnapshot(), e.World.NodeBeliefSnapshot()) {
		t.Fatalf("replay diverged:\n got  %+v\nwant %+v", replayed.NodeBeliefSnapshot(), e.World.NodeBeliefSnapshot())
	}
}

// TestNodeBeliefSet_Kind proves the event Kind() string, the same convention
// every other Timeline event in this package follows.
func TestNodeBeliefSet_Kind(t *testing.T) {
	if got := (NodeBeliefSet{}).Kind(); got != "node_belief.set" {
		t.Fatalf("NodeBeliefSet.Kind() = %q", got)
	}
}

// TestEngine_NodeBeliefs_ReadsLiveState proves the Engine-level accessor
// mirrors BetSettlements()'s own read-locked, tick-driven convention.
func TestEngine_NodeBeliefs_ReadsLiveState(t *testing.T) {
	e := NewEngine("t")
	e.Submit(NodeBeliefSet{Ref: NodeRef{Kind: NodeKindClaim, ID: "acme/1"}, Belief: Belief{Exploitable: 0.5}})
	e.Tick()

	got := e.NodeBeliefs()
	if len(got) != 1 || got[0].Belief.Exploitable != 0.5 {
		t.Fatalf("NodeBeliefs() = %+v, want one record with Exploitable=0.5", got)
	}
}

// TestWorldSnapshot_RoundTripsNodeBeliefs proves a snapshot+restore cycle
// reproduces every recorded node belief exactly — the same round-trip
// discipline gibson#278/#279/#280 hold BetSettlement to.
func TestWorldSnapshot_RoundTripsNodeBeliefs(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindClaim, ID: "acme/1"}, Belief: Belief{Exploitable: 0.7}, EvidenceDigest: "d1"})
	Reduce(w, NodeBeliefSet{Ref: NodeRef{Kind: NodeKindTechniqueEnvironment, ID: "sqli@web"}, Belief: Belief{Exploitable: 0.4}, EvidenceDigest: "d2"})

	snap := SnapshotWorld(w, "5")
	restored, err := RestoreWorld(snap, "t")
	if err != nil {
		t.Fatalf("RestoreWorld: %v", err)
	}
	if !reflect.DeepEqual(restored.NodeBeliefSnapshot(), w.NodeBeliefSnapshot()) {
		t.Fatalf("restore diverged:\n got  %+v\nwant %+v", restored.NodeBeliefSnapshot(), w.NodeBeliefSnapshot())
	}
}
