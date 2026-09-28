// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// belief_slice_gate.go extends belief.go's per-host evidence-digest gate to a
// SLICE-digest gate over the generic BeliefSubstrate (gibson#272) and the
// bounded slices gibson#286/#287 derive (ADR-0029 §8, gibson#289).
//
// The shape mirrors belief.go deliberately:
//
//   - SliceGate.Check (mechanical, cheap, no I/O — safe to call every tick)
//     compares a target's CURRENT slice-digest (its own belief-relevant state
//     PLUS every node in its bounded slice's) against the digest its
//     outstanding request was made for, and returns a SliceScoreRequested
//     only when they differ — the same "consulted once per change" gate
//     BeliefSystem runs for a single host's evidence.
//   - SliceBeliefWorker (off-tick) buffers requests (Tap, in-tick, no I/O)
//     and, on Drain, calls a SliceBeliefProvider (the sidecar's ground-slice
//     solver, gibson#288 — this package only defines the seam and a
//     deterministic placeholder, the same pattern BeliefProvider/
//     placeholderBelief/pgmpyBelief already establish) and applies the
//     result.
//   - SliceGate.Apply drops a SliceScored whose digest no longer matches the
//     outstanding request — the slice moved on while the model was scoring —
//     mirroring applyBeliefScored's staleness check.
//   - SliceGate.Invalidate / downstreamAffected implement "propagate bounded
//     to affected downstream nodes" (ADR-0029 §8): when a node's belief
//     changes, every node within a bounded number of forward enablement-edge
//     hops has that change re-checked on its next Check, instead of either
//     ignoring it (a stale downstream posterior) or re-checking the whole
//     graph every tick (an unbounded cascade).
//
// This gate is deliberately NOT wired into the ECS World/Timeline/Reduce (no
// change to brain.go's reducer switch): BeliefSubstrate's node kinds — Claim,
// TechniqueEnvironment — are not ECS entities yet, so there is no World
// state for a generic reducer to mutate. SliceGate is its own
// single-writer-over-its-own-state component (its methods take a lock the
// same way brain.World's tick-driven Reduce is the only mutator of ECS
// state), and TestSliceGate_ReplayReproducesTheSameSubstrateState proves the
// replay guarantee directly: folding the same recorded
// SliceScoreRequested/SliceScored sequence into a fresh SliceGate + substrate
// reproduces the same belief state, the same World==fold(Timeline) discipline
// belief.go's own tests hold the per-host gate to. Wiring this into the live
// engine tick loop (deriving `graph` from the World, driving a real
// SliceBeliefProvider over HTTP) is the belief engine proper, gibson#275.

// ScoredNode pairs a NodeRef with the NodeBelief a SliceBeliefProvider
// computed for it, so SliceScored can carry the (kind, id) a node needs to
// address BeliefSubstrate without a second lookup.
type ScoredNode struct {
	Ref    NodeRef
	Belief NodeBelief
}

// SliceScoreRequested records that target's slice-relevant state changed and
// that a (re)score for exactly Slice (as it stood at request time) was asked
// for. It carries the slice itself, mirroring BeliefScoreRequested carrying
// its evidence: the off-tick worker needs no read-back to score it.
type SliceScoreRequested struct {
	Target string
	Slice  AttackGraph
	Digest string
}

// Kind is the event's Timeline kind, for consistency with this package's
// event-sourced style. Not folded by the global Reduce — see the file doc.
func (SliceScoreRequested) Kind() string { return "belief.slice_requested" }

// SliceScored records a (re)computed belief for every node in the slice a
// SliceScoreRequested named, keyed to the digest that slice was scored at.
type SliceScored struct {
	Target string
	Nodes  []ScoredNode
	Digest string
}

// Kind is the event's Timeline kind. See SliceScoreRequested.Kind.
func (SliceScored) Kind() string { return "belief.slice_scored" }

// SliceBeliefProvider scores every node in a bounded slice at once (ADR-0029
// §5/§6). The real implementation calls the pgmpy sidecar's ground-slice
// solver (gibson#288, sidecar/belief/ground.py); this interface is the seam,
// and placeholderSliceBelief below is a deterministic stand-in, the same
// relationship BeliefProvider has to placeholderBelief/pgmpyBelief.
type SliceBeliefProvider interface {
	// ScoreSlice returns a NodeBelief for every node in slice, keyed by
	// AttackGraphNode.ID.
	ScoreSlice(slice AttackGraph) map[string]NodeBelief
	// Version is the model artifact the provider currently scores against.
	Version() string
}

// SliceDigest fingerprints target's slice-relevant STATE: every node in slice
// (already deterministically ordered by ExtractBoundedSlice/DeriveAttackGraph)
// paired with that node's current EVIDENCE digest from substrate, plus the
// slice's edge structure.
//
// This hashes EvidenceDigest, deliberately never Belief itself. Belief is the
// gate's own OUTPUT (Apply writes it); a digest built from it would be
// self-referential — every successful score would change the very state its
// own digest is measured against, and Check would request a rescore forever
// instead of settling to quiescence once nothing new has actually happened.
// EvidenceDigest is a stable INPUT fingerprint (belief.go's per-host gate
// already maintains it, untouched by applyBeliefScored) that changes only
// when new evidence arrives — mirroring the same input/output separation the
// per-host evidence-digest gate relies on. A belief-only change on an
// upstream node therefore does NOT, by itself, move a downstream node's
// digest; that propagation is SliceGate.Invalidate's job (ADR-0029 §8), not
// this digest's.
//
// Two calls over the same slice content and the same substrate state yield
// the same digest; a change to any node's EVIDENCE inside the slice, or to
// the slice's own shape, changes it — nothing else can.
func SliceDigest(ctx context.Context, slice AttackGraph, substrate BeliefSubstrate) (string, error) {
	type digestNode struct {
		ID             string `json:"id"`
		Kind           string `json:"kind"`
		EvidenceDigest string `json:"evidence_digest"`
	}
	nodes := make([]digestNode, 0, len(slice.Nodes))
	for _, n := range slice.Nodes {
		nb, _, err := substrate.Belief(ctx, NodeRef{Kind: NodeKind(n.Kind), ID: n.ID})
		if err != nil {
			return "", fmt.Errorf("slice digest: belief for %s %s: %w", n.Kind, n.ID, err)
		}
		nodes = append(nodes, digestNode{ID: n.ID, Kind: n.Kind, EvidenceDigest: nb.EvidenceDigest})
	}
	payload := struct {
		Nodes []digestNode `json:"nodes"`
		Edges []InfraEdge  `json:"edges"`
	}{Nodes: nodes, Edges: slice.Edges}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("slice digest: marshal payload: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SliceGate is the mechanical slice-digest gate: for each target it tracks
// the digest its outstanding request was made for, and drives Check/Apply/
// Invalidate against a BeliefSubstrate. All methods are safe for concurrent
// use.
type SliceGate struct {
	mu        sync.Mutex
	substrate BeliefSubstrate
	digests   map[string]string // target node id -> digest of its outstanding request
}

// NewSliceGate returns a gate backed by substrate (gibson#272).
func NewSliceGate(substrate BeliefSubstrate) *SliceGate {
	return &SliceGate{substrate: substrate, digests: make(map[string]string)}
}

// Check extracts target's bounded slice from graph (ExtractBoundedSlice,
// gibson#287), computes its current digest, and — only if that digest
// differs from the one target's outstanding request was made for — records
// the new digest and returns the SliceScoreRequested to emit. Returns
// (nil, nil) when nothing changed (quiescent). Cheap and I/O-free (aside from
// substrate reads, which are in-memory in every implementation this package
// ships): safe to call every tick without risking the ~50ms budget.
func (g *SliceGate) Check(
	ctx context.Context, graph AttackGraph, target string, opts SliceOptions, relevance map[string]float64,
) (*SliceScoreRequested, error) {
	slice := ExtractBoundedSlice(graph, target, opts, relevance)
	digest, err := SliceDigest(ctx, slice, g.substrate)
	if err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.digests[target] == digest {
		return nil, nil
	}
	g.digests[target] = digest
	return &SliceScoreRequested{Target: target, Slice: slice, Digest: digest}, nil
}

// Apply writes s's posteriors into the substrate and reports true, unless
// s.Digest no longer matches the digest recorded for s.Target — the slice
// moved on while the model was scoring, so a newer request is (or will be)
// outstanding, and s is dropped without touching the substrate. Mirrors
// applyBeliefScored's staleness check.
//
// A graph-coupled score answers for the SAME evidence a node already has —
// propagation refines the INFERENCE, it never observes new evidence — so
// Apply preserves each node's CURRENT EvidenceDigest rather than writing
// whatever s.Nodes[i].Belief.EvidenceDigest says (a SliceBeliefProvider has no
// business knowing a Host's per-evidence digest scheme; that would make every
// write look stale to a substrate like WorldBeliefSubstrate, whose backing
// store — belief.go's applyBeliefScored — rejects a BeliefScored event whose
// digest does not match the host's own recorded one).
func (g *SliceGate) Apply(ctx context.Context, s SliceScored) (bool, error) {
	g.mu.Lock()
	current, ok := g.digests[s.Target]
	g.mu.Unlock()
	if !ok || current != s.Digest {
		return false, nil
	}

	for _, n := range s.Nodes {
		existing, _, err := g.substrate.Belief(ctx, n.Ref)
		if err != nil {
			return false, fmt.Errorf("slice apply: read current belief for %s %s: %w", n.Ref.Kind, n.Ref.ID, err)
		}
		nb := n.Belief
		nb.EvidenceDigest = existing.EvidenceDigest
		if err := g.substrate.SetBelief(ctx, n.Ref, nb); err != nil {
			return false, fmt.Errorf("slice apply: set belief for %s %s: %w", n.Ref.Kind, n.Ref.ID, err)
		}
	}
	return true, nil
}

// Invalidate finds every node within opts of changed along FORWARD
// enablement edges (downstreamAffected) and clears their recorded digest, so
// each one's next Check treats its current slice-digest as changed — even if,
// mechanically, the natural recompute would already have noticed (changed's
// new belief is now part of their slice payload). The return value is the
// bounded set of ids a caller should re-Check next, rather than sweeping the
// whole graph — this is what makes the propagation bounded instead of an
// O(all nodes) scan every tick.
func (g *SliceGate) Invalidate(graph AttackGraph, changed string, opts SliceOptions) []string {
	affected := downstreamAffected(graph, changed, opts)
	g.mu.Lock()
	for _, id := range affected {
		delete(g.digests, id)
	}
	g.mu.Unlock()
	return affected
}

// downstreamAffected returns every node reachable from changed by following
// enablement edges FORWARD (successors — the mirror image of
// ExtractBoundedSlice's backward predecessor walk), bounded by opts.MaxDepth
// hops and opts.NodeBudget nodes (ADR-0029 §8: "propagate... bounded", no
// unbounded cascade). Sorted, so the result — and therefore which ids get
// invalidated — never depends on graph.Edges' input order.
func downstreamAffected(graph AttackGraph, changed string, opts SliceOptions) []string {
	successors := make(map[string][]string, len(graph.Nodes))
	for _, e := range graph.Edges {
		successors[e.From] = append(successors[e.From], e.To)
	}
	for from, tos := range successors {
		sort.Strings(tos)
		successors[from] = tos
	}

	depth := map[string]int{changed: 0}
	queue := []string{changed}
	var affected []string
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		d := depth[id]
		if opts.MaxDepth > 0 && d >= opts.MaxDepth {
			continue
		}
		for _, next := range successors[id] {
			if _, seen := depth[next]; seen {
				continue
			}
			depth[next] = d + 1
			affected = append(affected, next)
			queue = append(queue, next)
		}
	}

	sort.Strings(affected)
	if opts.NodeBudget > 0 && len(affected) > opts.NodeBudget {
		affected = affected[:opts.NodeBudget]
	}
	return affected
}

// SliceBeliefWorker drives the off-tick side of the slice-digest gate: Tap
// buffers SliceScoreRequested events (in-tick, no I/O); Drain scores every
// buffered request via the provider, applies each result through gate, and
// returns the bounded set of downstream ids Invalidate marked as needing a
// fresh Check next. Mirrors BeliefWorker/belief.go's Tap/Drain split exactly.
type SliceBeliefWorker struct {
	gate     *SliceGate
	provider SliceBeliefProvider

	mu      sync.Mutex
	pending []SliceScoreRequested
}

// NewSliceBeliefWorker builds a worker that scores gate's requests with p.
func NewSliceBeliefWorker(gate *SliceGate, p SliceBeliefProvider) *SliceBeliefWorker {
	return &SliceBeliefWorker{gate: gate, provider: p}
}

// Tap buffers req for the next Drain. Safe to call from the tick goroutine:
// it never touches the provider.
func (w *SliceBeliefWorker) Tap(req SliceScoreRequested) {
	w.mu.Lock()
	w.pending = append(w.pending, req)
	w.mu.Unlock()
}

// Drain scores every buffered request off the tick, applies each result, and
// invalidates that request's bounded downstream neighbourhood (propagateOpts)
// when the apply lands (not when it is dropped as stale — a stale score
// carries no new information to propagate). graph is the current whole-graph
// DAG (gibson#286), needed for downstream propagation. Returns how many
// requests were scored and the deduplicated, sorted union of every affected
// downstream id across all of them.
func (w *SliceBeliefWorker) Drain(ctx context.Context, graph AttackGraph, propagateOpts SliceOptions) (scored int, affected []string, err error) {
	w.mu.Lock()
	reqs := w.pending
	w.pending = nil
	w.mu.Unlock()

	affectedSet := make(map[string]struct{})
	for _, req := range reqs {
		result := w.provider.ScoreSlice(req.Slice)
		nodes := make([]ScoredNode, 0, len(req.Slice.Nodes))
		for _, n := range req.Slice.Nodes {
			nb, ok := result[n.ID]
			if !ok {
				continue
			}
			nodes = append(nodes, ScoredNode{Ref: NodeRef{Kind: NodeKind(n.Kind), ID: n.ID}, Belief: nb})
		}

		applied, applyErr := w.gate.Apply(ctx, SliceScored{Target: req.Target, Nodes: nodes, Digest: req.Digest})
		if applyErr != nil {
			return 0, nil, fmt.Errorf("slice drain: apply for target %s: %w", req.Target, applyErr)
		}
		if !applied {
			continue
		}
		for _, id := range w.gate.Invalidate(graph, req.Target, propagateOpts) {
			affectedSet[id] = struct{}{}
		}
	}

	affected = make([]string, 0, len(affectedSet))
	for id := range affectedSet {
		affected = append(affected, id)
	}
	sort.Strings(affected)
	return len(reqs), affected, nil
}

// placeholderSliceBelief is a deterministic stand-in SliceBeliefProvider
// (mirrors placeholderBelief in belief.go): every node's juicy/exploitable is
// the slice's edge-to-node ratio, reachable is always 1. NOT the real model —
// swapped for the pgmpy ground-slice sidecar (gibson#288) once gibson#275
// wires this seam into the live engine.
type placeholderSliceBelief struct{}

func (placeholderSliceBelief) ScoreSlice(slice AttackGraph) map[string]NodeBelief {
	out := make(map[string]NodeBelief, len(slice.Nodes))
	density := 0.0
	if len(slice.Nodes) > 0 {
		density = float64(len(slice.Edges)) / float64(len(slice.Nodes))
	}
	for _, n := range slice.Nodes {
		out[n.ID] = NodeBelief{
			Belief: Belief{Juicy: density, Exploitable: density, Reachable: 1, Model: "placeholder-slice-v0"},
		}
	}
	return out
}

func (placeholderSliceBelief) Version() string { return "placeholder-slice-v0" }

// PlaceholderSliceBeliefProvider returns the deterministic stand-in
// SliceBeliefProvider.
func PlaceholderSliceBeliefProvider() SliceBeliefProvider { return placeholderSliceBelief{} }
