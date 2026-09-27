// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"sync"
)

// belief_substrate.go is the stub/seam for ADR-0029: belief generalized to any
// node type the ontology declares belief variables for, not only Host.
//
// gibson#272 keeps the concrete work on the existing path — Host stays an ECS
// component scored by a BeliefProvider (belief.go) and projected with the node
// (graph_projector_neo4j.go). ADR-0029's full relational-PRM engine (a ground
// Bayesian attack graph, exact inference on a bounded slice) is out of scope
// here. What IS in scope is publishing the shape of the seam now, so the
// market and reputation views ADR-0029 §3 describes — a hypothesis/bet is
// belief on a claim-node, reputation is belief on a technique×environment
// node — can be built against one substrate rather than a bespoke store each,
// without waiting on the engine behind it.
//
// BeliefSubstrate is intentionally small and does not yet know about slices,
// enablement edges, or CPTs (ADR-0029 §§1,4-7) — those live behind whichever
// concrete implementation eventually backs it. Exactness is still the rule:
// a substrate may never sample (ADR-0005 §2), and a Write is expected to be
// logged as an event by its caller's engine, the same way BeliefScored is, so
// replay reproduces it.

// NodeKind identifies which ontology-declared node type a BeliefSubstrate call
// addresses. Host is the seed kind that already carries belief (gibson#272);
// Claim and TechniqueEnvironment are the two faces ADR-0029 §3 reframes as
// views over this substrate. Further kinds are declared by the ontology/Pack
// (ADR-0029 §2) as it grows — this list is not meant to stay closed.
type NodeKind string

const (
	// NodeKindHost is a Host entity (ADR-0005) — the belief seed content.
	NodeKindHost NodeKind = "host"
	// NodeKindClaim is a hypothesis/bet node: belief here is P(claim valid),
	// the market view (ADR-0022, reframed by ADR-0029 §3).
	NodeKindClaim NodeKind = "claim"
	// NodeKindTechniqueEnvironment is a technique×environment node: belief
	// here is P(technique works in this environment), the reputation view
	// (ADR-0029 §3).
	NodeKindTechniqueEnvironment NodeKind = "technique_environment"
)

// NodeRef addresses one belief-bearing node: its kind plus a stable id within
// that kind's own id space. Two refs of different Kind never collide even if
// their ID strings are equal — the ontology is what tells the ids apart, not
// this package.
type NodeRef struct {
	Kind NodeKind
	ID   string
}

// NodeBelief pairs a Belief with the evidence digest it was computed from —
// the same pairing Host carries today (Host.Belief / Host.EvidenceDigest,
// belief.go), generalized to any node. The digest is what lets a caller decide
// whether a recorded belief is still current for a node's evidence before
// trusting it, the same evidence-digest gate ADR-0005 §8 describes for Host.
type NodeBelief struct {
	Belief         Belief
	EvidenceDigest string
}

// BeliefSubstrate is the seam ADR-0029 §3 describes: read and write belief on
// any node the ontology declares belief variables for. It is synchronous and
// exact — never sampling, mirroring ADR-0005 §2 — and returns an error only
// for a genuine failure to read or write, never to signal "no belief yet"
// (that is the bool return).
type BeliefSubstrate interface {
	// Belief returns the belief currently recorded for ref, and whether ref
	// carries one at all. ok is false, not an error, before the first score.
	Belief(ctx context.Context, ref NodeRef) (nb NodeBelief, ok bool, err error)

	// SetBelief records nb as ref's current belief, replacing whatever was
	// there before in full — belief is never blended or averaged across
	// writes (ADR-0005 §2: exact and deterministic). A caller applying a
	// possibly-stale score is responsible for its own staleness check before
	// calling SetBelief, the same way applyBeliefScored checks
	// Host.EvidenceDigest before accepting a BeliefScored event.
	SetBelief(ctx context.Context, ref NodeRef, nb NodeBelief) error
}

// InMemoryBeliefSubstrate is a stub BeliefSubstrate: an in-process, unshared
// store with no persistence and no event log of its own. It exists so a
// caller can compile and test against BeliefSubstrate today — Lane C's market
// and reputation views, in particular — before a substrate backed by the
// relational-PRM engine (ADR-0029 §§1-2) exists. It is not wired into the
// Engine/World and does not replace the Host belief path (belief.go).
type InMemoryBeliefSubstrate struct {
	mu      sync.RWMutex
	beliefs map[NodeRef]NodeBelief
}

// NewInMemoryBeliefSubstrate returns an empty stub substrate.
func NewInMemoryBeliefSubstrate() *InMemoryBeliefSubstrate {
	return &InMemoryBeliefSubstrate{beliefs: make(map[NodeRef]NodeBelief)}
}

// Belief returns ref's recorded belief, if any.
func (s *InMemoryBeliefSubstrate) Belief(_ context.Context, ref NodeRef) (NodeBelief, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nb, ok := s.beliefs[ref]
	return nb, ok, nil
}

// SetBelief replaces ref's recorded belief with nb.
func (s *InMemoryBeliefSubstrate) SetBelief(_ context.Context, ref NodeRef, nb NodeBelief) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beliefs[ref] = nb
	return nil
}

var _ BeliefSubstrate = (*InMemoryBeliefSubstrate)(nil)
