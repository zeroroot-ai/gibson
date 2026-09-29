// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package brain — ontology_extension.go: agent-facing taxonomy/ontology
// extension PROPOSAL (ADR-0024 §2, ADR-0033 decision 2, gibson#391, epic
// #376).
//
// ADR-0033 decision 2's lifecycle is "Agent captures -> proposal (through the
// ValidIdentifier safety gate; PromotionGate observes recurrence and
// de-dupes) -> explicit tenant-owner approval -> tenant extension -> ...".
// This file builds the FIRST arrow only: an agent proposing a new Taxonomy
// node label or relationship type at runtime. It deliberately stops at
// "observe" — promotion into a live tenant extension is the tenant owner's
// explicit approval (gibson#392, not built here), and submitting a live
// extension upstream as a catalog contribution is a further step still
// (gibson#393, not built here either).
//
// The safety gate is deliberately STRICTER here than
// taxonomy.PromotionGate.Observe's own documented behavior. Observe never
// rejects anything — by design, because a raw sighting is data, never Cypher
// structure (see internal/engine/taxonomy/discovery.go) — but an agent that
// EXPLICITLY proposes an extension is asking for something to be recorded
// and eventually reviewed, not merely observed in passing. ProposeOntology-
// Extension therefore checks taxonomy.ValidIdentifier BEFORE Submitting
// anything: an invalid identifier is refused outright, fail-closed, and is
// never recorded as a sighting at all — it can never accumulate the
// recurrence a later promotion (gibson#392) would count.
//
// This is the "future integration" internal/engine/ontology/discovery.go's
// StructuralHypothesis doc anticipates ("a harness tool or daemon RPC that
// accepts an agent-proposed ontology extension"). It intentionally does NOT
// reuse ontology.StructuralHypothesis/ProposeExtension: that is ADR-0024 §1's
// LIGHT gate for ontology triples (classes/equivalences/IFPs), which never
// become Cypher structure and so need no ValidIdentifier check at all. A
// Taxonomy node label or relationship type is the opposite case — ADR-0024
// §2's HEAVY gate — because a promoted label DOES become Cypher query
// structure (taxonomy.PromotionGate's own doc explains why that gate is
// non-negotiable). The two proposal kinds intentionally stay separate
// Go-level concerns, the same way brain.Hypothesis and
// ontology.StructuralHypothesis stay separate types.
package brain

import (
	"context"
	"fmt"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// OntologyExtensionProposed records that an agent proposed a new Taxonomy
// node label or relationship type at runtime (ADR-0024 §2, ADR-0033 decision
// 2, gibson#391). Folding this event runs taxonomy.PromotionGate.Observe for
// this tenant, counting recurrence toward the eventual settlement gibson#392
// promotes on (recurrence + explicit tenant-owner HITL confirmation).
//
// The field is named ProposalKind, not Kind, so it never collides with the
// Event interface's own Kind() method.
type OntologyExtensionProposed struct {
	// ProposalKind distinguishes a proposed node label from a proposed
	// relationship type (taxonomy's own two vocabularies).
	ProposalKind taxonomy.ProposalKind
	// Label is the proposed identifier. By the time this event exists it has
	// already passed taxonomy.ValidIdentifier (ProposeOntologyExtension
	// checks this before Submit) — the fold never re-derives that decision,
	// it only counts recurrence.
	Label string
	// Proposer identifies the agent (or agent run) that proposed this
	// extension, carried through for audit/attribution — mirrors
	// ontology.StructuralHypothesis.Proposer.
	Proposer string
	// Claim is a short, free-text rationale for the proposal, carried
	// through for the tenant owner's eventual review (gibson#392) — mirrors
	// ontology.StructuralHypothesis.Claim.
	Claim string
}

// Kind identifies this event on the Timeline.
func (OntologyExtensionProposed) Kind() string { return "ontology_extension.proposed" }

// ontologyProposalKey identifies one proposed label independent of how many
// times it has been sighted — mirrors taxonomy's own unexported proposalKey.
type ontologyProposalKey struct {
	kind  taxonomy.ProposalKind
	label string
}

// OntologyProposalState is this tenant's current record of one proposed
// taxonomy label or relationship type: its running recurrence count and the
// most recent proposer/claim that sighted it. It is per-tenant fold state
// (ontologyProposals), not itself ECS-backed — like DomainPackState, a
// singleton-shaped value keyed by proposal identity rather than a growing
// collection of distinct sightings.
type OntologyProposalState struct {
	ProposalKind taxonomy.ProposalKind
	Label        string
	// Recurrence is taxonomy.PromotionGate.Observe's running count for this
	// (kind, label), as of the most recently folded sighting.
	Recurrence int
	// LastProposer and LastClaim carry the most recent sighting's
	// attribution and rationale. Earlier sightings' claims are not
	// separately retained here — gibson#392's approval flow reviews the
	// current state, not a full sighting history.
	LastProposer string
	LastClaim    string
}

// applyOntologyExtensionProposed is the reducer half of
// OntologyExtensionProposed: it runs PromotionGate.Observe for e's (kind,
// label) and records the resulting recurrence. Observe is always safe and
// never rejects (see taxonomy/discovery.go) — the safety gate that CAN
// reject already ran, in ProposeOntologyExtension, before this event was
// ever Submitted, so folding it is unconditional, exactly like every other
// apply* function in this package.
//
// Calling Observe here (inside the single-writer fold), rather than in
// ProposeOntologyExtension before Submit, is what makes recurrence counting
// replay-deterministic (ADR-0001): folding the identical sequence of
// OntologyExtensionProposed events against a fresh World reproduces the
// identical sequence of Observe calls, hence identical recurrence counts.
func applyOntologyExtensionProposed(w *World, e OntologyExtensionProposed) {
	recurrence := w.ontologyGate.Observe(e.ProposalKind, e.Label)
	w.ontologyProposals[ontologyProposalKey{kind: e.ProposalKind, label: e.Label}] = OntologyProposalState{
		ProposalKind: e.ProposalKind,
		Label:        e.Label,
		Recurrence:   recurrence,
		LastProposer: e.Proposer,
		LastClaim:    e.Claim,
	}
}

// OntologyProposalSnapshot is a stable, comparable view of one proposed
// taxonomy label or relationship type and its recurrence so far. This is the
// read model gibson#392's tenant-owner approval flow lists from; nothing in
// this package promotes it into the Taxonomy.
type OntologyProposalSnapshot struct {
	ProposalKind taxonomy.ProposalKind
	Label        string
	Recurrence   int
	LastProposer string
	LastClaim    string
}

// OntologyProposalSnapshot returns the tenant's currently observed ontology/
// taxonomy extension proposals, in deterministic (kind, then label) order.
func (w *World) OntologyProposalSnapshot() []OntologyProposalSnapshot {
	if len(w.ontologyProposals) == 0 {
		return nil
	}
	out := make([]OntologyProposalSnapshot, 0, len(w.ontologyProposals))
	for _, s := range w.ontologyProposals {
		out = append(out, OntologyProposalSnapshot(s))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProposalKind != out[j].ProposalKind {
			return out[i].ProposalKind < out[j].ProposalKind
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// OntologyDiscoveryEngine is the tenant-scoped capability a future
// ProposeOntologyExtension RPC needs (gibson#391, ADR-0024 §2, ADR-0033
// decision 2): fold a per-tenant OntologyExtensionProposed event through the
// ValidIdentifier safety gate and PromotionGate's recurrence counting. It
// mirrors ProofSettlementEngine's (proof_settlement.go) seam pattern
// exactly, for the same reason: nothing in this repo calls it yet.
//
// There is no existing agent-facing RPC or message this proposal can ride
// on: GetTaxonomySchema is read-only, ObserveRequest's oneof is a closed,
// fixed set of ten observation kinds (none of them structural), and
// HarnessCallbackService/ComponentService are the ONLY transport an agent
// (an SDK consumer) has to reach this daemon at all (ADR-0058 — the SDK is
// the component-dev surface). Wiring the actual RPC therefore needs a new
// message added to zeroroot-ai/sdk's harness_callback.proto, released, and
// pinned here — until then, *Engine (this file) is the seam a daemon-side
// tenant-routing adapter will wire directly, the same way
// internal/server/daemon/belief_substrate_adapter.go wires BeliefSubstrate.
type OntologyDiscoveryEngine interface {
	// ProposeOntologyExtension is Engine.ProposeOntologyExtension's contract
	// (see its doc).
	ProposeOntologyExtension(ctx context.Context, kind taxonomy.ProposalKind, label, proposer, claim string) error
}

var _ OntologyDiscoveryEngine = (*Engine)(nil)

// ProposeOntologyExtension is the entry point a future agent-facing RPC
// calls (gibson#391): an agent proposes a new Taxonomy node label or
// relationship type discovered at runtime. It is the ONLY exported way an
// OntologyExtensionProposed event reaches this Engine's intake, so "an
// invalid identifier never reaches the Timeline" holds by construction, not
// by caller discipline (mirrors PromotionGate.Promote's own guarantee).
//
// label is checked against taxonomy.ValidIdentifier BEFORE Submit and fails
// closed: an invalid identifier is refused outright and never recorded as a
// sighting, so it can never accumulate recurrence. proposer and claim are
// required, mirroring ontology.StructuralHypothesis's Proposer/Claim
// contract — an unattributed or unmotivated proposal cannot be audited or
// later evaluated by the tenant owner (gibson#392).
//
// Like SettleBetTrue/SettleBetFalse, the resulting OntologyExtensionProposed
// event is folded asynchronously through the normal single-writer Submit
// path (ADR-0001): a caller that needs the resulting recurrence count should
// read OntologyProposals() afterward rather than assume it is visible the
// instant this call returns.
func (e *Engine) ProposeOntologyExtension(_ context.Context, kind taxonomy.ProposalKind, label, proposer, claim string) error {
	if err := taxonomy.ValidIdentifier(label); err != nil {
		return &taxonomy.InvalidProposalError{Kind: kind, Label: label, Err: err}
	}
	if proposer == "" {
		return fmt.Errorf("brain: ontology extension proposal for %s %q has no proposer; an unattributed proposal cannot be audited", kind, label)
	}
	if claim == "" {
		return fmt.Errorf("brain: ontology extension proposal for %s %q has no claim text; an unmotivated proposal cannot be evaluated", kind, label)
	}
	e.Submit(OntologyExtensionProposed{
		ProposalKind: kind,
		Label:        label,
		Proposer:     proposer,
		Claim:        claim,
	})
	return nil
}

// OntologyProposals returns the tenant's currently observed ontology/
// taxonomy extension proposals (ADR-0024 §2, ADR-0033 decision 2,
// gibson#391).
func (e *Engine) OntologyProposals() []OntologyProposalSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.OntologyProposalSnapshot()
}
