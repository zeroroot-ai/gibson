// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "context"

// belief_substrate.go is the stub/seam for ADR-0129: belief generalized to any
// node type the ontology declares belief variables for, not only Host.
//
// gibson#272 keeps the concrete work on the existing path — Host stays an ECS
// component scored by a BeliefProvider (belief.go) and projected with the node
// (graph_projector_neo4j.go). ADR-0129's full relational-PRM engine (a ground
// Bayesian attack graph, exact inference on a bounded slice) is out of scope
// here. What IS in scope is publishing the shape of the seam now, so the
// market and reputation views ADR-0129 describes — a hypothesis/bet is
// belief on a claim-node, reputation is belief on a technique×environment
// node — can be built against one substrate rather than a bespoke store each,
// without waiting on the engine behind it.
//
// BeliefSubstrate is intentionally small and does not yet know about slices,
// enablement edges, or CPTs (ADR-0129) — those live behind whichever
// concrete implementation eventually backs it. Exactness is still the rule:
// a substrate may never sample (ADR-0134), and a Write is expected to be
// logged as an event by its caller's engine, the same way BeliefScored is, so
// replay reproduces it.

// NodeKind identifies which ontology-declared node type a BeliefSubstrate call
// addresses. Host is the seed kind that already carries belief (gibson#272);
// Claim and TechniqueEnvironment are the two faces ADR-0129 reframes as
// views over this substrate. Further kinds are declared by the ontology/Pack
// (ADR-0129) as it grows — this list is not meant to stay closed.
type NodeKind string

const (
	// NodeKindHost is a Host entity (ADR-0129) — the belief seed content.
	// Capitalized to match the taxonomy/ontology node-type convention
	// (taxonomy.go's hostLabels, ontology.NodeBeliefSchema.NodeType, every
	// InfraNode.Kind gibson#286/#287 produce all use "Host", never "host") —
	// NodeKind values are meant to interoperate directly with those strings,
	// not with a second, differently-cased vocabulary.
	NodeKindHost NodeKind = "Host"
	// NodeKindClaim is a hypothesis/bet node: belief here is P(claim valid),
	// the market view (ADR-0122, reframed by ADR-0129).
	NodeKindClaim NodeKind = "Claim"
	// NodeKindTechniqueEnvironment is a technique×environment node: belief
	// here is P(technique works in this environment), the reputation view
	// (ADR-0129).
	NodeKindTechniqueEnvironment NodeKind = "TechniqueEnvironment"
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
// trusting it, the same evidence-digest gate ADR-0129 describes for Host.
type NodeBelief struct {
	Belief         Belief
	EvidenceDigest string
	// CauseEdgeTypes are the enablement-edge types that fed the node in the
	// slice this belief was scored from (gibson#613). Sorted, unique.
	CauseEdgeTypes []string
}

// BeliefSubstrate is the seam ADR-0129 describes: read and write belief on
// any node the ontology declares belief variables for. It is synchronous and
// exact — never sampling, mirroring ADR-0134 — and returns an error only
// for a genuine failure to read or write, never to signal "no belief yet"
// (that is the bool return).
type BeliefSubstrate interface {
	// Belief returns the belief currently recorded for ref, and whether ref
	// carries one at all. ok is false, not an error, before the first score.
	Belief(ctx context.Context, ref NodeRef) (nb NodeBelief, ok bool, err error)

	// SetBelief records nb as ref's current belief, replacing whatever was
	// there before in full — belief is never blended or averaged across
	// writes (ADR-0134: exact and deterministic). A caller applying a
	// possibly-stale score is responsible for its own staleness check before
	// calling SetBelief, the same way applyBeliefScored checks
	// Host.EvidenceDigest before accepting a BeliefScored event.
	SetBelief(ctx context.Context, ref NodeRef, nb NodeBelief) error
}

// A concrete implementation is deliberately NOT published here. Publishing one
// with nothing in this repo calling it yet is unreachable from every cmd/
// entry point and fails the whole-program dead-code gate (make lint-deadcode) —
// so shipping a stub impl now would either force a premature
// .deadcode-baseline edit for code nothing uses, or force wiring it into a
// live path ahead of the view that needs it. The interface above is the seam
// gibson#272/ADR-0129 asks for; whichever lane builds the market/reputation
// view supplies (and reaches) its own backing implementation — an in-memory
// one initially, the relational-PRM engine (ADR-0129) eventually. See
// belief_substrate_test.go for a minimal implementation proving the interface
// is satisfiable and its semantics (round-trip, kind independence, exact
// overwrite) hold.
