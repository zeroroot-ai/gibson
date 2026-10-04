// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

func TestEdgeOutcomeObserved_FoldsIntoCountsPerEdgeType(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, EdgeOutcomeObserved{EdgeType: "RUNS_SERVICE", Success: true})
	Reduce(w, EdgeOutcomeObserved{EdgeType: "RUNS_SERVICE", Success: false})
	Reduce(w, EdgeOutcomeObserved{EdgeType: "AFFECTS", Success: true})
	Reduce(w, EdgeOutcomeObserved{EdgeType: "", Success: true})

	want := map[string]EdgeOutcomeCount{
		"RUNS_SERVICE": {Alpha: 1, Beta: 1},
		"AFFECTS":      {Alpha: 1},
	}
	if got := w.EdgeOutcomeCounts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("counts:\n got %+v\nwant %+v", got, want)
	}
	got := w.EdgeOutcomeCounts()
	got["AFFECTS"] = EdgeOutcomeCount{Alpha: 99}
	if w.EdgeOutcomeCounts()["AFFECTS"].Alpha != 1 {
		t.Fatal("EdgeOutcomeCounts must return a copy")
	}
}

func TestSliceCauseEdgeTypes_SortedUniqueIncomingOnly(t *testing.T) {
	slice := AttackGraph{Edges: []InfraEdge{
		{Type: "RUNS_SERVICE", From: "a", To: "target"},
		{Type: "AFFECTS", From: "b", To: "target"},
		{Type: "RUNS_SERVICE", From: "c", To: "target"},
		{Type: "ISSUED", From: "target", To: "d"},
		{Type: "", From: "e", To: "target"},
	}}
	if got, want := sliceCauseEdgeTypes(slice, "target"), []string{"AFFECTS", "RUNS_SERVICE"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := sliceCauseEdgeTypes(slice, "a"); got != nil {
		t.Fatalf("a node with no incoming edge must carry nil, got %v", got)
	}
}

// TestNativeScoreSlice_CarriesTheCauseEdgeTypes proves the scorer records, per
// node, the enablement-edge types the slice fed it with, so the gate writes
// them into the World with the belief.
func TestNativeScoreSlice_CarriesTheCauseEdgeTypes(t *testing.T) {
	reg := ontology.NewBeliefSchemaRegistry()
	require.NoError(t, reg.RegisterExtension("core/belief-schema", ontology.SeedBeliefSchemaExtension()))
	nodes := []InfraNode{{ID: "1", Kind: "Host"}, {ID: "2", Kind: "Host"}}
	edges := []InfraEdge{{Type: "RUNS_SERVICE", From: "1", To: "2"}, {Type: "AFFECTS", From: "1", To: "2"}}
	graph := DeriveAttackGraph(nodes, edges, reg)

	out := NativeSliceBeliefProvider(reg, nil).ScoreSlice(graph)
	if got := out["2"].CauseEdgeTypes; !reflect.DeepEqual(got, []string{"AFFECTS", "RUNS_SERVICE"}) {
		t.Fatalf("node 2 causes = %v", got)
	}
	if got := out["1"].CauseEdgeTypes; got != nil {
		t.Fatalf("node 1 has no cause, got %v", got)
	}
}

// settleTwoBetsOnOneSlice drives the whole path through an engine: a scored
// host carrying two cause edge types, two hypotheses about that host, one
// settled FALSE by exhaustion and one settled TRUE by HITL. It returns the
// engine after both settlements folded.
func settleTwoBetsOnOneSlice(t *testing.T, e *Engine) {
	t.Helper()
	ctx := context.Background()
	e.Submit(HostObserved{ScopeID: "s1", Address: "10.0.0.7", OpenPorts: []int{22}})
	e.Tick()
	hosts := e.Hosts()
	require.Len(t, hosts, 1)

	// The gate's write, with the slice's cause edge types attached.
	sub := NewWorldBeliefSubstrate(e)
	require.NoError(t, sub.SetBelief(ctx, NodeRef{Kind: NodeKindHost, ID: HostNodeID(hosts[0].ID)}, NodeBelief{
		Belief: Belief{Reachable: 0.9}, EvidenceDigest: hosts[0].EvidenceDigest,
		CauseEdgeTypes: []string{"AFFECTS", "RUNS_SERVICE"},
	}))
	e.Tick()
	require.Equal(t, []string{"AFFECTS", "RUNS_SERVICE"}, e.Hosts()[0].CauseEdgeTypes)

	ref := []ReferencedEntityRef{{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.7"}}}
	e.Submit(HypothesisObserved{ScopeID: "s1", MissionID: "m1", Claim: "ssh is weak", HypothesisID: "hyp-a", Technique: "T1110", References: ref})
	e.Submit(HypothesisObserved{ScopeID: "s1", MissionID: "m1", Claim: "ssh is open", HypothesisID: "hyp-b", Technique: "T1190", References: ref})
	e.Tick()

	settled, err := e.SettleBetFalse(ctx, BetExhaustionRequest{HypothesisID: "hyp-a", MissionID: "m1", AttemptBudget: 1, AttemptsMade: 1, Reason: "budget"})
	require.NoError(t, err)
	require.True(t, settled)
	settled, err = e.SettleBetByHITL(ctx, BetHITLRequest{HypothesisID: "hyp-b", MissionID: "m1", UserID: "alice", Verdict: VerdictTruePositive})
	require.NoError(t, err)
	require.True(t, settled)
	e.Tick()
	e.Tick()
}

var wantTwoBetCounts = map[string]EdgeOutcomeCount{
	"AFFECTS":      {Alpha: 1, Beta: 1},
	"RUNS_SERVICE": {Alpha: 1, Beta: 1},
}

// TestEdgeOutcomes_TwoBetsOnOneSlice_CountPerEdgeTypeAndReplay settles two
// bets on one slice and asserts the counts per edge type, then proves the
// same Timeline re-folds to the same counts.
func TestEdgeOutcomes_TwoBetsOnOneSlice_CountPerEdgeTypeAndReplay(t *testing.T) {
	e := NewEngine("acme")
	settleTwoBetsOnOneSlice(t, e)

	if got := e.EdgeOutcomeCounts(); !reflect.DeepEqual(got, wantTwoBetCounts) {
		t.Fatalf("live counts:\n got %+v\nwant %+v", got, wantTwoBetCounts)
	}

	tl := &Timeline{}
	kinds := map[string]int{}
	for _, ev := range e.Events() {
		tl.Append(ev)
		kinds[ev.Kind()]++
	}
	require.Equal(t, 4, kinds["edge.outcome_observed"], "one outcome per cause edge type per settled bet")
	replayed := Replay("acme", tl)
	if got := replayed.EdgeOutcomeCounts(); !reflect.DeepEqual(got, wantTwoBetCounts) {
		t.Fatalf("replayed counts:\n got %+v\nwant %+v", got, wantTwoBetCounts)
	}
}

// TestEdgeOutcomes_UnknownHypothesisEmitsNothing proves a settlement on a
// hypothesis the World does not know, or one whose host carries no cause
// edge types, records a settlement and no outcome.
func TestEdgeOutcomes_UnknownHypothesisEmitsNothing(t *testing.T) {
	e := NewEngine("acme")
	_, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{HypothesisID: "ghost", AttemptBudget: 1, AttemptsMade: 1, Reason: "budget"})
	require.NoError(t, err)
	e.Tick()
	e.Tick()
	require.Len(t, e.BetSettlements(), 1)
	require.Empty(t, e.EdgeOutcomeCounts())
}

func TestEdgeOutcomeObserved_RoundTripsTheCodec(t *testing.T) {
	in := EdgeOutcomeObserved{EdgeType: "AFFECTS", Success: true, MissionID: "m1", ScopeID: "s1"}
	b, err := EncodeEvent(in)
	require.NoError(t, err)
	out, err := DecodeEvent(b)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

// memTimelineStore is an in-memory TimelineStore: an append-only stream
// with sequence ids, a single snapshot slot, and a trim that drops the
// prefix a snapshot covers. It exists so the snapshot round trip below runs
// against the same three calls the engine makes on the durable store.
type memTimelineStore struct {
	mu     sync.Mutex
	events []memEvent
	next   int
	snap   *WorldSnapshot
}

type memEvent struct {
	seq int
	ev  Event
}

func (s *memTimelineStore) Append(_ context.Context, _ string, ev Event) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	s.events = append(s.events, memEvent{seq: s.next, ev: ev})
	return seqString(s.next), nil
}

func (s *memTimelineStore) LoadForReplay(_ context.Context, _, afterSeq string) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	after := 0
	if afterSeq != "" {
		after = parseSeq(afterSeq)
	}
	var out []Event
	for _, me := range s.events {
		if me.seq > after {
			out = append(out, me.ev)
		}
	}
	return out, nil
}

func (s *memTimelineStore) WriteSnapshot(_ context.Context, _ string, snap WorldSnapshot) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := snap
	s.snap = &cp
	return snap.AtSeq, nil
}

func (s *memTimelineStore) LoadSnapshot(_ context.Context, _ string) (*WorldSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap == nil {
		return nil, nil
	}
	cp := *s.snap
	return &cp, nil
}

func (s *memTimelineStore) TrimTo(_ context.Context, _, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	upTo := parseSeq(handle)
	kept := s.events[:0]
	for _, me := range s.events {
		if me.seq > upTo {
			kept = append(kept, me)
		}
	}
	s.events = kept
	return nil
}

func (s *memTimelineStore) remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func seqString(n int) string { return strconv.Itoa(n) }

func parseSeq(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// TestEdgeOutcomes_SurviveWriteSnapshotTrimToLoadSnapshot proves the counts
// are carried by the snapshot: the engine snapshots after every event and
// trims the stream, so a fresh engine hydrating from the store sees the
// counts with no outcome event left to replay.
func TestEdgeOutcomes_SurviveWriteSnapshotTrimToLoadSnapshot(t *testing.T) {
	store := &memTimelineStore{}
	e := NewEngine("acme").WithStore(store).WithSnapshotCadence(1)
	settleTwoBetsOnOneSlice(t, e)
	require.Equal(t, 0, store.remaining(), "a cadence of one trims every event behind the snapshot")

	fresh := NewEngine("acme").WithStore(store)
	fresh.Hydrate(context.Background())
	if got := fresh.EdgeOutcomeCounts(); !reflect.DeepEqual(got, wantTwoBetCounts) {
		t.Fatalf("hydrated counts:\n got %+v\nwant %+v", got, wantTwoBetCounts)
	}

	// The snapshot lists the counts in edge-type order.
	snap := e.World.EdgeOutcomeSnapshot()
	types := make([]string, 0, len(snap))
	for _, s := range snap {
		types = append(types, s.EdgeType)
	}
	require.True(t, sort.StringsAreSorted(types))
}
