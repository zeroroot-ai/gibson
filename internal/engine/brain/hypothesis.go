// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"maps"
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// hypothesis.go folds an emitted Hypothesis (ADR-0121, gibson#265) into the
// World as the second provenance class next to Evidence (Host, Domain, ...;
// brain.go and friends) and Belief (belief.go). A Hypothesis is an agent's
// proposed, unproven claim — attributed to its proposer, carrying a
// confidence — that stays unverified until a later slice settles it
// (ADR-0122/0123's betting/settlement path). It folds through the normal
// Observe -> reducer path exactly like an Evidence observation (ADR-0107),
// keeping the agent write surface emit-only, but it lands as its own
// provenance class: Reduce never derives a Belief from a Hypothesis, and
// nothing in belief.go reads a Hypothesis. The three provenance classes stay
// distinct by construction — separate event types, separate ECS components,
// separate reducer functions — not by convention alone.
//
// Scope: this is ADR-0107's "S1 observation vocabulary" slice (events +
// reducers + the ambient World projection), matching gibson#265's acceptance
// criteria exactly. Materializing a :Hypothesis node into the per-tenant
// Neo4j read-model is ADR-0107's separate "S3 graph projector" concern
// (internal/server/daemon/graph_projector.go, which already projects Host,
// Domain, Entity, ... one type at a time) — left for a later slice, the same
// way S1 landed for every other observation kind well before its graph
// projection did.

// ReferencedEntityRef names an entity a Hypothesis is about, by Taxonomy
// label and identity properties rather than a World/graph node id — the same
// by-label-and-properties addressing ADR-0107 uses for a typed lifecycle
// entity sighting (entity.go's EntitySighting), so a proposing agent never
// has to know or guess a node id. Resolving a reference into an actual graph
// edge to the named entity is out of scope for this fold: References is
// stored as reported, for a later slice to resolve.
type ReferencedEntityRef struct {
	Label        string
	IDProperties map[string]string
}

// Hypothesis is an agent's proposed, unproven claim (ADR-0121) — the
// "Hypothesis" provenance class, distinct from Evidence (Host, Domain, ...;
// an agent's sighting of something real) and Belief (belief.go; the PGM's
// computed posterior). Confidence is the proposer's own calibrated estimate
// of the claim, never a computed Belief: nothing here ever sets Belief, and
// belief.go never reads Hypothesis.
type Hypothesis struct {
	// ID is a stable, replay-deterministic id (assigned at creation) for
	// event references and graph projection — the same role Host.ID plays.
	// It is NOT the identifier a PlaceBet or settlement call names — an
	// agent can never learn this world-assigned id back (Observe has no
	// return value carrying it), so it cannot be what a later Bet
	// references. See HypothesisID for that join key (gibson#339).
	ID uint64
	// ScopeID partitions identity the same way it does for Host: two
	// networks proposing the identical claim text are different hypotheses
	// (ADR-0102, scope-relative identity).
	ScopeID string
	// Claim states the hypothesis in a form the brain can later settle, e.g.
	// "port 6443 on this host is unauthenticated". Together with ScopeID,
	// this is the hypothesis's identity: a second observation of the same
	// (ScopeID, Claim) enriches this node rather than creating a duplicate —
	// recurrence of the same proposal is signal, not noise (ADR-0124).
	Claim string
	// Proposer identifies the agent that first made the claim. A later
	// observation of the same (ScopeID, Claim) by a different agent does
	// not reassign Proposer: attribution stays with whoever proposed it
	// first, the same progressive-enrichment rule Host.MissionID follows.
	Proposer string
	// Confidence is the most recently reported calibrated confidence for
	// this claim. Unlike Proposer, a later observation DOES overwrite this:
	// confidence is the proposer's live estimate, not an identity signal,
	// and there is exactly one current value per hypothesis, not a history.
	Confidence float64
	// References names the entities the claim is about. Re-observation
	// unions new references into the existing set (dedup, order-preserving)
	// — the same accretive rule Entity.Edges uses (entity.go, unionEdges).
	References []ReferencedEntityRef
	// MissionID is the mission whose agent proposed this hypothesis — the
	// mission-evidence edge, the same role Host.MissionID plays.
	MissionID string
	// HypothesisID is the agent-chosen identifier the proposing agent set on
	// HypothesisObservation (sdk#70/hypothesis_id field). This is the one
	// join key across Hypothesis, Bet and BetSettlement (gibson#339): a Bet
	// names the same value as Bet.HypothesisId, and a settlement
	// (Engine.SettleBetByHITL, gibson#280, and the other two settlement
	// paths) records against it. Progressive-enrichment, same rule as
	// Proposer: kept from whichever observation first supplied one, never
	// reassigned once set — an in-flight Bet must never have its target
	// silently repointed. May be empty: a Hypothesis with no id still folds
	// as a claim, it just cannot be staked on or settled by id.
	HypothesisID string
	// RunID is the mission run whose agent proposed this hypothesis
	// (ContextInfo.mission_run_id on the wire), for transcript linking
	// (gibson#339's ListOpenBets). Same progressive-enrichment rule as
	// MissionID.
	RunID string
	// Technique names the technique this hypothesis exercises
	// (HypothesisObservation.technique, sdk#88). Reputation keys on
	// technique x environment (ADR-0122, gibson#333/#284), so this must ride
	// on the Hypothesis the same way it already rides on Bet.
	// Progressive-enrichment, same rule as HypothesisID: kept from whichever
	// observation first supplied one, never reassigned — a later,
	// possibly-differently-labeled re-observation must not silently
	// repoint reputation credit. May be empty: a Hypothesis with no
	// technique carries no reputation signal (resolves to the neutral
	// prior), the same behavior as before this field existed.
	Technique string
}

// HypothesisObserved records that an agent proposed a claim about the target
// (ADR-0121, sdk#70's HypothesisObservation). It folds through the normal
// Observe -> reducer path exactly like an Evidence observation (ADR-0107),
// so it is replayable like any other event, but it lands as the Hypothesis
// provenance class — never as Evidence, and never as a Belief.
type HypothesisObserved struct {
	MissionID    string
	RunID        string
	ScopeID      string
	Proposer     string
	Confidence   float64
	Claim        string
	HypothesisID string
	Technique    string
	References   []ReferencedEntityRef
}

// Kind identifies the hypothesis.observed brain event.
func (HypothesisObserved) Kind() string { return "hypothesis.observed" }

// applyHypothesisObserved folds a HypothesisObserved event into the World.
// (ScopeID, Claim) is the hypothesis's identity: a matching hypothesis is
// enriched (confidence refreshed to the latest report, references unioned,
// proposer kept from the first observation, mission attribution kept from
// the first observation); no match creates a new Hypothesis with a fresh,
// replay-deterministic id. A claim with no text records nothing — there
// would be no stable node for another agent to pick up and test.
func applyHypothesisObserved(w *World, e HypothesisObserved) {
	if e.Claim == "" {
		return
	}

	q := ecs.NewFilter1[Hypothesis](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		if h.ScopeID != e.ScopeID || h.Claim != e.Claim {
			continue
		}
		if h.Proposer == "" {
			h.Proposer = e.Proposer
		}
		h.Confidence = e.Confidence
		h.References = unionReferences(h.References, e.References)
		if h.MissionID == "" {
			h.MissionID = e.MissionID
		}
		if h.RunID == "" {
			h.RunID = e.RunID
		}
		if h.HypothesisID == "" {
			h.HypothesisID = e.HypothesisID
		}
		if h.Technique == "" {
			h.Technique = e.Technique
		}
		q.Close()
		return
	}
	// Query exhausted → world unlocked.

	w.hypotheses.NewEntity(&Hypothesis{
		ID:           w.newHypothesisID(),
		ScopeID:      e.ScopeID,
		Claim:        e.Claim,
		Proposer:     e.Proposer,
		Confidence:   e.Confidence,
		References:   unionReferences(nil, e.References),
		MissionID:    e.MissionID,
		RunID:        e.RunID,
		HypothesisID: e.HypothesisID,
		Technique:    e.Technique,
	})
}

// unionReferences appends every reference in add that base does not already
// hold, preserving order so replay is deterministic — the same accretive
// rule unionEdges (entity.go) applies to Entity.Edges. A reference with no
// label is dropped: there would be nothing to address.
func unionReferences(base, add []ReferencedEntityRef) []ReferencedEntityRef {
	out := append([]ReferencedEntityRef(nil), base...)
	for _, ref := range add {
		if ref.Label == "" {
			continue
		}
		dup := false
		for _, have := range out {
			if have.Label == ref.Label && maps.Equal(have.IDProperties, ref.IDProperties) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, ReferencedEntityRef{Label: ref.Label, IDProperties: maps.Clone(ref.IDProperties)})
		}
	}
	return out
}

// HypothesisSnapshot is a stable, comparable view of a Hypothesis — what the
// ambient projection (WorldView) surfaces to other agents so the fleet can
// pick up a claim and test it (ADR-0121).
type HypothesisSnapshot struct {
	ID           uint64
	ScopeID      string
	Claim        string
	Proposer     string
	Confidence   float64
	References   []ReferencedEntityRef
	MissionID    string
	RunID        string
	HypothesisID string
	Technique    string
}

// HypothesisSnapshot returns hypotheses in deterministic (ScopeID, Claim)
// order.
func (w *World) HypothesisSnapshot() []HypothesisSnapshot {
	var out []HypothesisSnapshot
	q := ecs.NewFilter1[Hypothesis](w.ecs).Query()
	for q.Next() {
		h := q.Get()
		out = append(out, HypothesisSnapshot{
			ID:           h.ID,
			ScopeID:      h.ScopeID,
			Claim:        h.Claim,
			Proposer:     h.Proposer,
			Confidence:   h.Confidence,
			References:   append([]ReferencedEntityRef(nil), h.References...),
			MissionID:    h.MissionID,
			RunID:        h.RunID,
			HypothesisID: h.HypothesisID,
			Technique:    h.Technique,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Claim < out[j].Claim
	})
	return out
}
