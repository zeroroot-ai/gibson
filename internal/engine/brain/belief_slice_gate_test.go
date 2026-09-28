// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// erroringBeliefSubstrate wraps a fakeBeliefSubstrate but can be told to fail
// (or to hand back an unmarshalable belief) for one specific NodeRef, so
// SliceDigest/Check/Apply/Drain's error-propagation branches — which a
// substrate that never fails can never exercise — have something to trigger
// them.
type erroringBeliefSubstrate struct {
	*fakeBeliefSubstrate
	failBeliefFor    NodeRef
	failSetBeliefFor NodeRef
	nanBeliefFor     NodeRef
}

func (s *erroringBeliefSubstrate) Belief(ctx context.Context, ref NodeRef) (NodeBelief, bool, error) {
	if ref == s.failBeliefFor {
		return NodeBelief{}, false, errors.New("boom: belief read failed")
	}
	if ref == s.nanBeliefFor {
		return NodeBelief{Belief: Belief{Juicy: math.NaN()}}, true, nil
	}
	return s.fakeBeliefSubstrate.Belief(ctx, ref)
}

func (s *erroringBeliefSubstrate) SetBelief(ctx context.Context, ref NodeRef, nb NodeBelief) error {
	if ref == s.failSetBeliefFor {
		return errors.New("boom: set belief failed")
	}
	return s.fakeBeliefSubstrate.SetBelief(ctx, ref, nb)
}

// chainSliceGraph builds A -> B -> C -> D (each an enablement edge), all
// belief-bearing Host nodes, via the real DeriveAttackGraph (gibson#286) —
// the same fixture shape belief_attack_graph_test.go and belief_slice_test.go
// use, reused here so the gate's tests exercise the real graph/slice types.
func chainSliceGraph(t *testing.T) AttackGraph {
	t.Helper()
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{
		{ID: "a", Kind: "Host"}, {ID: "b", Kind: "Host"},
		{ID: "c", Kind: "Host"}, {ID: "d", Kind: "Host"},
	}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "a", To: "b"},
		{Type: "RESOLVES_TO", From: "b", To: "c"},
		{Type: "RESOLVES_TO", From: "c", To: "d"},
	}
	return DeriveAttackGraph(nodes, edges, reg)
}

// fakeSliceBeliefProvider is a test double: it counts calls and reports the
// number of open causes as juicy/exploitable (mirroring countingBelief in
// belief_test.go), optionally blocking until release is closed — used to
// prove the gate's Check step never waits on it.
type fakeSliceBeliefProvider struct {
	mu      sync.Mutex
	calls   int
	release chan struct{}
}

func (p *fakeSliceBeliefProvider) ScoreSlice(slice AttackGraph) map[string]NodeBelief {
	p.mu.Lock()
	p.calls++
	release := p.release
	p.mu.Unlock()
	if release != nil {
		<-release
	}
	out := make(map[string]NodeBelief, len(slice.Nodes))
	for _, n := range slice.Nodes {
		juicy := float64(len(slice.Edges)) / float64(len(slice.Nodes)+1)
		out[n.ID] = NodeBelief{
			Belief:         Belief{Juicy: juicy, Exploitable: juicy, Reachable: 1, Model: "fake-v0"},
			EvidenceDigest: "",
		}
	}
	return out
}

func (p *fakeSliceBeliefProvider) Version() string { return "fake-v0" }

func (p *fakeSliceBeliefProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// TestSliceGate_QuiescentUntilSliceChanges proves the mechanical gate: a
// first Check for a target always requests a score (nothing recorded yet);
// an immediately repeated Check with nothing changed is quiescent (nil, no
// request) — the same "consulted once per change, not once per sweep"
// invariant belief.go's BeliefSystem holds for evidence.
func TestSliceGate_QuiescentUntilSliceChanges(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := newFakeBeliefSubstrate()
	gate := NewSliceGate(substrate)
	ctx := context.Background()

	req, err := gate.Check(ctx, graph, "d", SliceOptions{}, nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if req == nil {
		t.Fatalf("first Check for a target must always request a score")
	}
	if req.Target != "d" {
		t.Fatalf("Target = %q, want d", req.Target)
	}

	req2, err := gate.Check(ctx, graph, "d", SliceOptions{}, nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if req2 != nil {
		t.Fatalf("repeated Check with nothing changed requested again: %+v", req2)
	}
}

// TestSliceGate_DetectsChangeInsideTheSliceOnly proves the digest is scoped
// to the bounded slice: a belief change on a node INSIDE target's slice
// re-triggers a request; a change on a node OUTSIDE it (not reachable
// backward from target within the bound) does not.
func TestSliceGate_DetectsChangeInsideTheSliceOnly(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := newFakeBeliefSubstrate()
	gate := NewSliceGate(substrate)
	ctx := context.Background()

	if _, err := gate.Check(ctx, graph, "b", SliceOptions{MaxDepth: 1}, nil); err != nil {
		t.Fatalf("Check: %v", err)
	}

	// "d" is not in b's depth-1 backward slice ({a, b}): changing it must not
	// move b's slice-digest.
	if err := substrate.SetBelief(ctx, NodeRef{Kind: NodeKindHost, ID: "d"}, NodeBelief{Belief: Belief{Juicy: 0.9}}); err != nil {
		t.Fatalf("SetBelief(d): %v", err)
	}
	req, err := gate.Check(ctx, graph, "b", SliceOptions{MaxDepth: 1}, nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if req != nil {
		t.Fatalf("a change outside the bounded slice triggered a request: %+v", req)
	}

	// "a" IS in b's depth-1 backward slice: changing it must move the digest.
	if err := substrate.SetBelief(ctx, NodeRef{Kind: NodeKindHost, ID: "a"}, NodeBelief{Belief: Belief{Juicy: 0.9}}); err != nil {
		t.Fatalf("SetBelief(a): %v", err)
	}
	req, err = gate.Check(ctx, graph, "b", SliceOptions{MaxDepth: 1}, nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if req == nil {
		t.Fatalf("a change inside the bounded slice did not trigger a request")
	}
}

// TestSliceGate_AppliesFreshAndDropsStale mirrors
// TestBeliefScored_StaleResultIsDropped (belief_test.go): a SliceScored whose
// digest matches the outstanding request is applied to the substrate; one
// whose digest has been superseded is dropped without touching it.
func TestSliceGate_AppliesFreshAndDropsStale(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := newFakeBeliefSubstrate()
	gate := NewSliceGate(substrate)
	ctx := context.Background()

	req, err := gate.Check(ctx, graph, "d", SliceOptions{}, nil)
	if err != nil || req == nil {
		t.Fatalf("setup Check: req=%+v err=%v", req, err)
	}

	fresh := SliceScored{
		Target: "d",
		Digest: req.Digest,
		Nodes: []ScoredNode{
			{Ref: NodeRef{Kind: NodeKindHost, ID: "d"}, Belief: NodeBelief{Belief: Belief{Juicy: 0.42}}},
		},
	}
	applied, err := gate.Apply(ctx, fresh)
	if err != nil {
		t.Fatalf("Apply(fresh): %v", err)
	}
	if !applied {
		t.Fatalf("a score matching the outstanding digest was not applied")
	}
	nb, ok, err := substrate.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: "d"})
	if err != nil || !ok || nb.Belief.Juicy != 0.42 {
		t.Fatalf("substrate after fresh apply: nb=%+v ok=%v err=%v", nb, ok, err)
	}

	stale := SliceScored{
		Target: "d",
		Digest: "digest-of-a-slice-state-d-has-moved-past",
		Nodes: []ScoredNode{
			{Ref: NodeRef{Kind: NodeKindHost, ID: "d"}, Belief: NodeBelief{Belief: Belief{Juicy: 0.99}}},
		},
	}
	applied, err = gate.Apply(ctx, stale)
	if err != nil {
		t.Fatalf("Apply(stale): %v", err)
	}
	if applied {
		t.Fatalf("a stale score was applied")
	}
	nb, ok, err = substrate.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: "d"})
	if err != nil || !ok || nb.Belief.Juicy != 0.42 {
		t.Fatalf("stale apply changed the substrate: nb=%+v ok=%v err=%v", nb, ok, err)
	}
}

// TestDownstreamAffected_IsBoundedNotUnbounded is the acceptance criterion's
// "no unbounded cascade": in the A->B->C->D chain, invalidating from "a" must
// reach only as far as opts.MaxDepth allows.
func TestDownstreamAffected_IsBoundedNotUnbounded(t *testing.T) {
	graph := chainSliceGraph(t)

	tests := []struct {
		depth int
		want  []string
	}{
		{depth: 1, want: []string{"b"}},
		{depth: 2, want: []string{"b", "c"}},
		{depth: 3, want: []string{"b", "c", "d"}},
		{depth: 100, want: []string{"b", "c", "d"}},
	}
	for _, tc := range tests {
		got := downstreamAffected(graph, "a", SliceOptions{MaxDepth: tc.depth})
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("MaxDepth=%d: downstreamAffected = %v, want %v", tc.depth, got, tc.want)
		}
	}

	bounded := downstreamAffected(graph, "a", SliceOptions{NodeBudget: 1})
	if !reflect.DeepEqual(bounded, []string{"b"}) {
		t.Errorf("NodeBudget=1: got %v, want [b] (unbounded depth, but capped node count)", bounded)
	}
}

// TestSliceGate_InvalidatePropagatesDownstreamBounded proves the gate uses
// downstreamAffected to actually force a re-check on affected nodes: after
// Invalidate, a previously-quiescent downstream target reports a change on
// its next Check, while a node beyond the propagation bound stays quiescent.
func TestSliceGate_InvalidatePropagatesDownstreamBounded(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := newFakeBeliefSubstrate()
	gate := NewSliceGate(substrate)
	ctx := context.Background()
	// Every node's OWN slice is depth-1-bounded, same as the propagation
	// bound below: "a" is in b's slice ({a,b}) but NOT in c's ({b,c}), so a
	// natural recompute of c's digest cannot see a's change either — the only
	// way c could re-request here is if Invalidate wrongly reached it.
	nodeOpts := SliceOptions{MaxDepth: 1}

	// Settle b, c and d against the initial (empty) substrate state.
	for _, id := range []string{"b", "c", "d"} {
		if _, err := gate.Check(ctx, graph, id, nodeOpts, nil); err != nil {
			t.Fatalf("settle Check(%s): %v", id, err)
		}
	}
	for _, id := range []string{"b", "c", "d"} {
		if req, err := gate.Check(ctx, graph, id, nodeOpts, nil); err != nil || req != nil {
			t.Fatalf("setup: %s not quiescent: req=%+v err=%v", id, req, err)
		}
	}

	// "a" changes; propagate one hop.
	if err := substrate.SetBelief(ctx, NodeRef{Kind: NodeKindHost, ID: "a"}, NodeBelief{Belief: Belief{Juicy: 0.7}}); err != nil {
		t.Fatalf("SetBelief(a): %v", err)
	}
	affected := gate.Invalidate(graph, "a", SliceOptions{MaxDepth: 1})
	if !reflect.DeepEqual(affected, []string{"b"}) {
		t.Fatalf("Invalidate returned %v, want [b]", affected)
	}

	if req, err := gate.Check(ctx, graph, "b", nodeOpts, nil); err != nil || req == nil {
		t.Fatalf("b (within the propagation bound) did not re-request after Invalidate: req=%+v err=%v", req, err)
	}
	if req, err := gate.Check(ctx, graph, "c", nodeOpts, nil); err != nil || req != nil {
		t.Fatalf("c (beyond the propagation bound) requested after a bounded Invalidate: req=%+v err=%v", req, err)
	}
}

// TestSliceBeliefWorker_DrainScoresAndAppliesThenInvalidates runs the full
// off-tick cycle: Tap buffers a request, Drain calls the provider, applies
// the result, and returns the bounded downstream ids to re-check next —
// wiring Check -> Tap -> Drain -> Apply -> Invalidate end to end.
func TestSliceBeliefWorker_DrainScoresAndAppliesThenInvalidates(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := newFakeBeliefSubstrate()
	gate := NewSliceGate(substrate)
	provider := &fakeSliceBeliefProvider{}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()

	req, err := gate.Check(ctx, graph, "b", SliceOptions{MaxDepth: 1}, nil)
	if err != nil || req == nil {
		t.Fatalf("Check: req=%+v err=%v", req, err)
	}
	worker.Tap(*req)

	scored, affected, err := worker.Drain(ctx, graph, SliceOptions{MaxDepth: 1})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if scored != 1 {
		t.Fatalf("Drain scored %d requests, want 1", scored)
	}
	if !reflect.DeepEqual(affected, []string{"c"}) {
		t.Fatalf("Drain returned affected=%v, want [c] (one hop downstream of b)", affected)
	}
	if provider.count() != 1 {
		t.Fatalf("provider called %d times, want 1", provider.count())
	}

	nb, ok, err := substrate.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: "b"})
	if err != nil || !ok {
		t.Fatalf("substrate after drain: nb=%+v ok=%v err=%v", nb, ok, err)
	}
	if nb.Belief.Model != "fake-v0" {
		t.Fatalf("applied belief has Model=%q, want fake-v0", nb.Belief.Model)
	}

	// Quiescent: draining again with nothing new tapped does no work.
	if scored, _, err := worker.Drain(ctx, graph, SliceOptions{MaxDepth: 1}); err != nil || scored != 0 {
		t.Fatalf("second Drain scored %d (err=%v), want 0", scored, err)
	}
}

// TestSliceBeliefWorker_SlowProviderDoesNotStallCheck proves Check (the
// mechanical, in-tick gate) never touches the provider, so a slow Drain
// running concurrently never blocks it — the same guarantee
// TestBeliefWorker_SlowProviderDoesNotStallTick proves for the per-host gate.
func TestSliceBeliefWorker_SlowProviderDoesNotStallCheck(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := newFakeBeliefSubstrate()
	gate := NewSliceGate(substrate)
	release := make(chan struct{})
	provider := &fakeSliceBeliefProvider{release: release}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()

	req, err := gate.Check(ctx, graph, "d", SliceOptions{}, nil)
	if err != nil || req == nil {
		t.Fatalf("Check: req=%+v err=%v", req, err)
	}
	worker.Tap(*req)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = worker.Drain(ctx, graph, SliceOptions{})
	}()
	waitFor(t, func() bool { return provider.count() == 1 })

	start := time.Now()
	for range 20 {
		if _, err := gate.Check(ctx, graph, "a", SliceOptions{}, nil); err != nil {
			t.Fatalf("Check(a) while Drain was blocked: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed >= 200*time.Millisecond {
		t.Fatalf("20 Checks took %v while the provider slept indefinitely — Check waited on it", elapsed)
	}

	close(release)
	<-done
}

// TestSliceGate_ReplayReproducesTheSameSubstrateState is the acceptance
// criterion's "replay reproduces the propagated field exactly": record every
// Requested/Scored event from a live run, then fold the SAME event sequence
// into a fresh SliceGate + substrate and require byte-identical resulting
// belief state — the same World==fold(Timeline) discipline belief.go's own
// tests hold the per-host gate to (TestBelief_ScoredQuiescentReplay), applied
// to slice-belief state instead of ECS Host state.
func TestSliceGate_ReplayReproducesTheSameSubstrateState(t *testing.T) {
	graph := chainSliceGraph(t)
	live := newFakeBeliefSubstrate()
	gate := NewSliceGate(live)
	provider := &fakeSliceBeliefProvider{}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()

	requested := make([]SliceScoreRequested, 0, 4)
	scoredLog := make([]SliceScored, 0, 4)

	for _, id := range []string{"a", "b", "c", "d"} {
		req, err := gate.Check(ctx, graph, id, SliceOptions{MaxDepth: 2}, nil)
		if err != nil {
			t.Fatalf("Check(%s): %v", id, err)
		}
		if req == nil {
			continue
		}
		requested = append(requested, *req)
		worker.Tap(*req)
	}
	// Capture the SliceScored events Drain produces by scoring one request at
	// a time (Drain's own internals are opaque; rebuild the log the way a
	// real off-tick worker would submit it, via the provider directly, so the
	// replay test exercises the SAME construction Drain uses).
	for _, req := range requested {
		result := provider.ScoreSlice(req.Slice)
		nodes := make([]ScoredNode, 0, len(req.Slice.Nodes))
		for _, n := range req.Slice.Nodes {
			nb, ok := result[n.ID]
			if !ok {
				continue
			}
			nodes = append(nodes, ScoredNode{Ref: NodeRef{Kind: NodeKind(n.Kind), ID: n.ID}, Belief: nb})
		}
		s := SliceScored{Target: req.Target, Digest: req.Digest, Nodes: nodes}
		scoredLog = append(scoredLog, s)
		if _, err := gate.Apply(ctx, s); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}

	// Replay: fresh gate + substrate, fold the SAME recorded events in the
	// SAME order.
	replaySubstrate := newFakeBeliefSubstrate()
	replayGate := NewSliceGate(replaySubstrate)
	for _, req := range requested {
		// Check re-derives the identical request deterministically from the
		// same (graph, target, opts) — folding Requested itself is a no-op on
		// substrate state (mirrors applyBeliefScoreRequested, which only
		// records the digest, never belief); what matters for replay is that
		// re-deriving it is possible and matches, which the digest equality
		// below proves.
		got, err := replayGate.Check(ctx, graph, req.Target, SliceOptions{MaxDepth: 2}, nil)
		if err != nil {
			t.Fatalf("replay Check(%s): %v", req.Target, err)
		}
		if got == nil || got.Digest != req.Digest {
			t.Fatalf("replay re-derived a different request for %s: got=%+v want digest %s", req.Target, got, req.Digest)
		}
	}
	for _, s := range scoredLog {
		if _, err := replayGate.Apply(ctx, s); err != nil {
			t.Fatalf("replay Apply: %v", err)
		}
	}

	for _, id := range []string{"a", "b", "c", "d"} {
		ref := NodeRef{Kind: NodeKindHost, ID: id}
		live, liveOK, err := live.Belief(ctx, ref)
		if err != nil {
			t.Fatalf("live.Belief(%s): %v", id, err)
		}
		replayed, replayOK, err := replaySubstrate.Belief(ctx, ref)
		if err != nil {
			t.Fatalf("replayed.Belief(%s): %v", id, err)
		}
		if liveOK != replayOK || live != replayed {
			t.Fatalf("%s diverged: live=%+v(%v) replayed=%+v(%v)", id, live, liveOK, replayed, replayOK)
		}
	}
}

// TestDownstreamAffected_DeterministicAcrossEdgeOrder proves the cascade
// bound does not depend on the caller's edge order, the same replay-safety
// property gibson#286/#287 hold their own outputs to.
func TestDownstreamAffected_DeterministicAcrossEdgeOrder(t *testing.T) {
	graph := chainSliceGraph(t)
	reversed := AttackGraph{
		Nodes: append([]AttackGraphNode(nil), graph.Nodes...),
		Edges: append([]InfraEdge(nil), graph.Edges...),
	}
	sort.Slice(reversed.Edges, func(i, j int) bool { return reversed.Edges[i].Type > reversed.Edges[j].Type })
	for i, j := 0, len(reversed.Edges)-1; i < j; i, j = i+1, j-1 {
		reversed.Edges[i], reversed.Edges[j] = reversed.Edges[j], reversed.Edges[i]
	}

	a := downstreamAffected(graph, "a", SliceOptions{MaxDepth: 5})
	b := downstreamAffected(reversed, "a", SliceOptions{MaxDepth: 5})
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("order-dependent: %v vs %v", a, b)
	}
}

// TestSliceEvents_Kind pins both event Kinds, the same way
// TestBeliefEvents_CodecRoundTrip (belief_test.go) pins BeliefScoreRequested/
// BeliefScored's.
func TestSliceEvents_Kind(t *testing.T) {
	if got := (SliceScoreRequested{}).Kind(); got != "belief.slice_requested" {
		t.Fatalf("SliceScoreRequested.Kind() = %q, want belief.slice_requested", got)
	}
	if got := (SliceScored{}).Kind(); got != "belief.slice_scored" {
		t.Fatalf("SliceScored.Kind() = %q, want belief.slice_scored", got)
	}
}

// TestPlaceholderSliceBeliefProvider exercises the deterministic stand-in
// provider directly: density is edges/nodes, reachable is always 1, and the
// empty-graph edge case (zero nodes) does not divide by zero.
func TestPlaceholderSliceBeliefProvider(t *testing.T) {
	p := PlaceholderSliceBeliefProvider()
	if p.Version() != "placeholder-slice-v0" {
		t.Fatalf("Version() = %q, want placeholder-slice-v0", p.Version())
	}

	slice := AttackGraph{
		Nodes: []AttackGraphNode{{InfraNode: InfraNode{ID: "a", Kind: "Host"}}, {InfraNode: InfraNode{ID: "b", Kind: "Host"}}},
		Edges: []InfraEdge{{Type: "RESOLVES_TO", From: "a", To: "b"}},
	}
	out := p.ScoreSlice(slice)
	if len(out) != 2 {
		t.Fatalf("got %d scored nodes, want 2", len(out))
	}
	for _, id := range []string{"a", "b"} {
		nb := out[id]
		if nb.Belief.Juicy != 0.5 || nb.Belief.Exploitable != 0.5 {
			t.Errorf("%s: Juicy/Exploitable = %v/%v, want 0.5/0.5 (1 edge / 2 nodes)", id, nb.Belief.Juicy, nb.Belief.Exploitable)
		}
		if nb.Belief.Reachable != 1 {
			t.Errorf("%s: Reachable = %v, want 1", id, nb.Belief.Reachable)
		}
		if nb.Belief.Model != "placeholder-slice-v0" {
			t.Errorf("%s: Model = %q, want placeholder-slice-v0", id, nb.Belief.Model)
		}
	}

	if out := p.ScoreSlice(AttackGraph{}); len(out) != 0 {
		t.Fatalf("empty slice: got %d scored nodes, want 0", len(out))
	}
}

// TestSliceDigest_PropagatesSubstrateError proves a substrate read failure
// surfaces as an error rather than silently digesting a zero-value belief.
func TestSliceDigest_PropagatesSubstrateError(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := &erroringBeliefSubstrate{
		fakeBeliefSubstrate: newFakeBeliefSubstrate(),
		failBeliefFor:       NodeRef{Kind: NodeKindHost, ID: "a"},
	}
	slice := ExtractBoundedSlice(graph, "b", SliceOptions{MaxDepth: 1}, nil)

	_, err := SliceDigest(context.Background(), slice, substrate)
	if err == nil {
		t.Fatalf("SliceDigest did not propagate the substrate error")
	}
}

// TestSliceDigest_PropagatesMarshalError proves a belief that cannot be
// JSON-marshaled (a NaN float) surfaces as an error rather than a digest
// silently computed over truncated/garbage JSON.
func TestSliceDigest_PropagatesMarshalError(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := &erroringBeliefSubstrate{
		fakeBeliefSubstrate: newFakeBeliefSubstrate(),
		nanBeliefFor:        NodeRef{Kind: NodeKindHost, ID: "a"},
	}
	slice := ExtractBoundedSlice(graph, "b", SliceOptions{MaxDepth: 1}, nil)

	_, err := SliceDigest(context.Background(), slice, substrate)
	if err == nil {
		t.Fatalf("SliceDigest did not propagate the json.Marshal error for a NaN belief")
	}
}

// TestSliceGate_Check_PropagatesDigestError proves Check surfaces a
// SliceDigest failure rather than treating it as "nothing changed".
func TestSliceGate_Check_PropagatesDigestError(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := &erroringBeliefSubstrate{
		fakeBeliefSubstrate: newFakeBeliefSubstrate(),
		failBeliefFor:       NodeRef{Kind: NodeKindHost, ID: "a"},
	}
	gate := NewSliceGate(substrate)

	req, err := gate.Check(context.Background(), graph, "b", SliceOptions{MaxDepth: 1}, nil)
	if err == nil {
		t.Fatalf("Check did not propagate the digest error")
	}
	if req != nil {
		t.Fatalf("Check returned a request alongside an error: %+v", req)
	}
}

// TestSliceGate_Apply_PropagatesSetBeliefError proves Apply surfaces a
// substrate write failure rather than reporting a silent success.
func TestSliceGate_Apply_PropagatesSetBeliefError(t *testing.T) {
	graph := chainSliceGraph(t)
	failRef := NodeRef{Kind: NodeKindHost, ID: "d"}
	substrate := &erroringBeliefSubstrate{fakeBeliefSubstrate: newFakeBeliefSubstrate(), failSetBeliefFor: failRef}
	gate := NewSliceGate(substrate)
	ctx := context.Background()

	req, err := gate.Check(ctx, graph, "d", SliceOptions{}, nil)
	if err != nil || req == nil {
		t.Fatalf("setup Check: req=%+v err=%v", req, err)
	}

	applied, err := gate.Apply(ctx, SliceScored{
		Target: "d",
		Digest: req.Digest,
		Nodes:  []ScoredNode{{Ref: failRef, Belief: NodeBelief{Belief: Belief{Juicy: 0.5}}}},
	})
	if err == nil {
		t.Fatalf("Apply did not propagate the substrate SetBelief error")
	}
	if applied {
		t.Fatalf("Apply reported success alongside an error")
	}
}

// TestSliceBeliefWorker_Drain_PropagatesApplyError proves Drain surfaces an
// Apply failure instead of swallowing it.
func TestSliceBeliefWorker_Drain_PropagatesApplyError(t *testing.T) {
	graph := chainSliceGraph(t)
	failRef := NodeRef{Kind: NodeKindHost, ID: "d"}
	substrate := &erroringBeliefSubstrate{fakeBeliefSubstrate: newFakeBeliefSubstrate(), failSetBeliefFor: failRef}
	gate := NewSliceGate(substrate)
	provider := &fakeSliceBeliefProvider{}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()

	req, err := gate.Check(ctx, graph, "d", SliceOptions{}, nil)
	if err != nil || req == nil {
		t.Fatalf("setup Check: req=%+v err=%v", req, err)
	}
	worker.Tap(*req)

	if _, _, err := worker.Drain(ctx, graph, SliceOptions{}); err == nil {
		t.Fatalf("Drain did not propagate the Apply error")
	}
}

// TestSliceBeliefWorker_Drain_SkipsNodesMissingFromProviderResult proves a
// provider that under-reports (returns no belief for a node the slice
// includes) does not crash the drain — that node is simply left unscored
// this round, not force-fed a zero value.
func TestSliceBeliefWorker_Drain_SkipsNodesMissingFromProviderResult(t *testing.T) {
	graph := chainSliceGraph(t)
	substrate := newFakeBeliefSubstrate()
	gate := NewSliceGate(substrate)
	provider := &partialSliceBeliefProvider{omit: "a"}
	worker := NewSliceBeliefWorker(gate, provider)
	ctx := context.Background()

	req, err := gate.Check(ctx, graph, "b", SliceOptions{MaxDepth: 1}, nil)
	if err != nil || req == nil {
		t.Fatalf("setup Check: req=%+v err=%v", req, err)
	}
	worker.Tap(*req)

	scored, _, err := worker.Drain(ctx, graph, SliceOptions{MaxDepth: 1})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if scored != 1 {
		t.Fatalf("scored = %d, want 1", scored)
	}

	if _, ok, _ := substrate.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: "a"}); ok {
		t.Fatalf("a's belief was written despite being omitted from the provider's result")
	}
	if _, ok, _ := substrate.Belief(ctx, NodeRef{Kind: NodeKindHost, ID: "b"}); !ok {
		t.Fatalf("b's belief (present in the provider's result) was not written")
	}
}

// partialSliceBeliefProvider is a SliceBeliefProvider that omits one node id
// from its result, simulating a real solver that could not score every node.
type partialSliceBeliefProvider struct{ omit string }

func (p *partialSliceBeliefProvider) ScoreSlice(slice AttackGraph) map[string]NodeBelief {
	out := make(map[string]NodeBelief, len(slice.Nodes))
	for _, n := range slice.Nodes {
		if n.ID == p.omit {
			continue
		}
		out[n.ID] = NodeBelief{Belief: Belief{Juicy: 1, Reachable: 1, Model: "partial-v0"}}
	}
	return out
}

func (p *partialSliceBeliefProvider) Version() string { return "partial-v0" }

// TestDownstreamAffected_HandlesDiamondWithoutDuplicates proves a node
// reachable by two different forward paths (a diamond: a->b, a->c, b->d,
// c->d) is invalidated once, not twice, and BFS does not revisit it.
func TestDownstreamAffected_HandlesDiamondWithoutDuplicates(t *testing.T) {
	reg := testBeliefRegistry(t)
	nodes := []InfraNode{
		{ID: "a", Kind: "Host"}, {ID: "b", Kind: "Host"},
		{ID: "c", Kind: "Host"}, {ID: "d", Kind: "Host"},
	}
	edges := []InfraEdge{
		{Type: "RESOLVES_TO", From: "a", To: "b"},
		{Type: "RESOLVES_TO", From: "a", To: "c"},
		{Type: "RESOLVES_TO", From: "b", To: "d"},
		{Type: "RESOLVES_TO", From: "c", To: "d"},
	}
	graph := DeriveAttackGraph(nodes, edges, reg)

	got := downstreamAffected(graph, "a", SliceOptions{})
	want := []string{"b", "c", "d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("downstreamAffected = %v, want %v (d must appear exactly once)", got, want)
	}
}
