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
// explicit approval (gibson#392, not built here). Submitting a live
// extension upstream as a catalog contribution is the further step gibson#393
// builds, in ontology_extension_upstream.go.
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

// OntologyExtensionApproved records that the tenant owner explicitly
// approved a previously-proposed Taxonomy node label or relationship type
// (ADR-0033 decision 3, gibson#392). Folding this event runs
// taxonomy.PromotionGate.Confirm for this tenant — the HITL half of
// settlement — and attempts Promote; the label becomes a live, per-tenant
// taxonomy extension immediately once BOTH settlement halves (recurrence and
// this approval) are satisfied.
//
// The field is named ProposalKind, not Kind, for the same reason
// OntologyExtensionProposed's is: it never collides with the Event
// interface's own Kind() method.
type OntologyExtensionApproved struct {
	// ProposalKind and Label identify which pending proposal this approval
	// decides — must match a prior OntologyExtensionProposed's fields
	// exactly (taxonomy's own (kind, label) proposal identity).
	ProposalKind taxonomy.ProposalKind
	Label        string
	// Reviewer identifies the tenant owner who approved this proposal,
	// carried through for audit/attribution and recorded as
	// taxonomy.PromotionGate's Confirm reviewer.
	Reviewer string
}

// Kind identifies this event on the Timeline.
func (OntologyExtensionApproved) Kind() string { return "ontology_extension.approved" }

// OntologyExtensionRejected records that the tenant owner explicitly
// rejected a previously-proposed Taxonomy node label or relationship type
// (ADR-0033 decision 3, gibson#392). Folding this event never touches
// taxonomy.PromotionGate — a rejected proposal is simply never Confirmed, so
// it can never be promoted through this tenant's gate. Terminal: this
// package exposes no "undo a rejection" event.
type OntologyExtensionRejected struct {
	// ProposalKind and Label identify which pending proposal this rejection
	// decides — same identity contract as OntologyExtensionApproved's.
	ProposalKind taxonomy.ProposalKind
	Label        string
	// Reviewer identifies the tenant owner who rejected this proposal.
	Reviewer string
	// Reason is the tenant owner's free-text rationale for rejecting,
	// carried through for audit.
	Reason string
}

// Kind identifies this event on the Timeline.
func (OntologyExtensionRejected) Kind() string { return "ontology_extension.rejected" }

// ontologyProposalKey identifies one proposed label independent of how many
// times it has been sighted — mirrors taxonomy's own unexported proposalKey.
type ontologyProposalKey struct {
	kind  taxonomy.ProposalKind
	label string
}

// OntologyProposalStatus is a proposed taxonomy label or relationship type's
// current position in ADR-0033 decision 2's lifecycle, as observed by this
// tenant's World: proposed and awaiting a decision, explicitly approved by
// the tenant owner, or explicitly rejected. It is independent of Promoted
// (below) — an OntologyProposalApproved proposal that has not yet recurred
// taxonomy.MinRecurrenceForSettlement times is Approved but not yet
// Promoted; a later sighting completes promotion without another approval.
type OntologyProposalStatus int

const (
	// OntologyProposalPending is the initial state: observed at least once,
	// awaiting the tenant owner's explicit approval or rejection (gibson#392).
	OntologyProposalPending OntologyProposalStatus = iota
	// OntologyProposalApproved records that the tenant owner approved this
	// proposal (the HITL half of taxonomy.PromotionGate's settlement rule).
	OntologyProposalApproved
	// OntologyProposalRejected records that the tenant owner rejected this
	// proposal. Terminal: nothing in this package promotes a rejected
	// proposal, and there is no "undo a rejection" path.
	OntologyProposalRejected
)

// String renders s for error messages and the approval-queue read model.
func (s OntologyProposalStatus) String() string {
	switch s {
	case OntologyProposalPending:
		return "pending"
	case OntologyProposalApproved:
		return "approved"
	case OntologyProposalRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// OntologyProposalState is this tenant's current record of one proposed
// taxonomy label or relationship type: its running recurrence count, the
// most recent proposer/claim that sighted it, and the tenant owner's
// decision (if any) plus whether that decision has produced a live taxonomy
// extension yet. It is per-tenant fold state (ontologyProposals), not itself
// ECS-backed — like DomainPackState, a singleton-shaped value keyed by
// proposal identity rather than a growing collection of distinct sightings.
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
	// Status is this proposal's position in the approval lifecycle
	// (gibson#392, ADR-0033 decision 3). Zero value is OntologyProposalPending.
	Status OntologyProposalStatus
	// Reviewer is the tenant owner who approved or rejected this proposal.
	// Empty while Status is Pending.
	Reviewer string
	// RejectReason is the tenant owner's free-text rationale for rejecting
	// this proposal. Empty unless Status is Rejected.
	RejectReason string
	// Promoted is true once taxonomy.PromotionGate.Promote has actually
	// admitted this label into the tenant's live Taxonomy (ontologyGate.Base()) —
	// the authoritative "is this a live tenant extension yet" signal.
	// Status == OntologyProposalApproved alone does NOT imply Promoted: the
	// proposal may still be short of taxonomy.MinRecurrenceForSettlement
	// independent sightings.
	Promoted bool
	// PromotedVersion is the resulting taxonomy.Registry version once
	// Promoted is true; zero otherwise.
	PromotedVersion int
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
//
// A later sighting can complete settlement for a proposal the tenant owner
// already approved (gibson#392) before it had recurred enough times: after
// updating recurrence, promoteIfSettled retries Promote for an
// already-Approved, not-yet-Promoted proposal, so the owner never has to
// approve the same proposal twice.
func applyOntologyExtensionProposed(w *World, e OntologyExtensionProposed) {
	recurrence := w.ontologyGate.Observe(e.ProposalKind, e.Label)
	key := ontologyProposalKey{kind: e.ProposalKind, label: e.Label}
	state := w.ontologyProposals[key]
	state.ProposalKind = e.ProposalKind
	state.Label = e.Label
	state.Recurrence = recurrence
	state.LastProposer = e.Proposer
	state.LastClaim = e.Claim
	promoteIfSettled(w, key, &state)
	w.ontologyProposals[key] = state
}

// applyOntologyExtensionApproved is the reducer half of
// OntologyExtensionApproved (ADR-0033 decision 3, gibson#392): the tenant
// owner's explicit approval is the HITL half of taxonomy.PromotionGate's
// settlement rule. Folding this event runs PromotionGate.Confirm for e's
// (kind, label) — recording the reviewer — then attempts promoteIfSettled:
// once the SAME proposal has ALSO recurred taxonomy.MinRecurrenceForSettlement
// times (the automated half, already tracked by applyOntologyExtensionProposed),
// promotion succeeds and the label becomes live, per-tenant, replayable
// Cypher structure immediately (w.ontologyGate.Base() advances).
//
// Calling Confirm/Promote here (inside the single-writer fold), rather than
// in Engine.ApproveOntologyExtension before Submit, keeps this
// replay-deterministic for the same reason applyOntologyExtensionProposed's
// own Observe call does.
//
// A missing proposal (no prior OntologyExtensionProposed ever folded for
// this key) or a Confirm failure (ValidIdentifier, which
// Engine.ApproveOntologyExtension already checked before Submit) are both
// impossible via the only exported path to this event — folding stays
// defined for every input regardless, never panicking on a fold path,
// mirroring the rest of this package's discipline.
func applyOntologyExtensionApproved(w *World, e OntologyExtensionApproved) {
	key := ontologyProposalKey{kind: e.ProposalKind, label: e.Label}
	state, ok := w.ontologyProposals[key]
	if !ok {
		return
	}
	if err := w.ontologyGate.Confirm(e.ProposalKind, e.Label, e.Reviewer); err != nil {
		return
	}
	state.Status = OntologyProposalApproved
	state.Reviewer = e.Reviewer
	promoteIfSettled(w, key, &state)
	w.ontologyProposals[key] = state
}

// applyOntologyExtensionRejected is the reducer half of
// OntologyExtensionRejected (ADR-0033 decision 3, gibson#392): records the
// tenant owner's explicit rejection. This never touches ontologyGate — a
// rejected proposal is simply never Confirmed, so PromotionGate.Promote can
// never admit it; rejection is audit state, not a Taxonomy mutation.
func applyOntologyExtensionRejected(w *World, e OntologyExtensionRejected) {
	key := ontologyProposalKey{kind: e.ProposalKind, label: e.Label}
	state, ok := w.ontologyProposals[key]
	if !ok {
		return
	}
	state.Status = OntologyProposalRejected
	state.Reviewer = e.Reviewer
	state.RejectReason = e.Reason
	w.ontologyProposals[key] = state
}

// promoteIfSettled attempts taxonomy.PromotionGate.Promote for key and
// records the outcome onto state in place. It is the ONE place either fold
// path (applyOntologyExtensionProposed or applyOntologyExtensionApproved)
// calls Promote, so a proposal is never promoted twice nor by two different
// code paths — settlement is symmetric in its two halves (recurrence and
// HITL confirmation, ADR-0033 decision 2), and whichever half completes
// last is the one that actually triggers promotion.
//
// A no-op once state.Promoted is already true, or while state.Status is not
// yet Approved (nothing to attempt). A taxonomy.NotSettledError from Promote
// (insufficient recurrence) is an expected, not-yet-settled outcome — not a
// fold-time invariant violation — so it is silently absorbed here; the next
// qualifying sighting or approval retries.
func promoteIfSettled(w *World, key ontologyProposalKey, state *OntologyProposalState) {
	if state.Promoted || state.Status != OntologyProposalApproved {
		return
	}
	registry, err := w.ontologyGate.Promote(key.kind, key.label)
	if err != nil {
		return
	}
	state.Promoted = true
	state.PromotedVersion = registry.Version()
}

// OntologyProposalSnapshot is a stable, comparable view of one proposed
// taxonomy label or relationship type, its recurrence so far, and the tenant
// owner's decision (if any). This is the read model gibson#392's
// tenant-owner approval flow (OntologyExtensionService, ListOntologyExtensionProposals)
// lists from.
type OntologyProposalSnapshot struct {
	ProposalKind    taxonomy.ProposalKind
	Label           string
	Recurrence      int
	LastProposer    string
	LastClaim       string
	Status          OntologyProposalStatus
	Reviewer        string
	RejectReason    string
	Promoted        bool
	PromotedVersion int
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

// OntologyProposalNotFoundError is returned by ApproveOntologyExtension and
// RejectOntologyExtension when (kind, label) names no proposal this tenant's
// World has ever observed.
type OntologyProposalNotFoundError struct {
	Kind  taxonomy.ProposalKind
	Label string
}

func (e *OntologyProposalNotFoundError) Error() string {
	return fmt.Sprintf("brain: no ontology extension proposal found for %s %q", e.Kind, e.Label)
}

// OntologyProposalAlreadyDecidedError is returned by ApproveOntologyExtension
// and RejectOntologyExtension when (kind, label) already carries a terminal
// tenant-owner decision. The tenant owner's decision is per-proposal and
// final through this seam — there is no "change your mind" path, so a second
// decision on the same proposal is refused rather than silently overwriting
// the first.
type OntologyProposalAlreadyDecidedError struct {
	Kind   taxonomy.ProposalKind
	Label  string
	Status OntologyProposalStatus
}

func (e *OntologyProposalAlreadyDecidedError) Error() string {
	return fmt.Sprintf("brain: ontology extension proposal for %s %q was already %s", e.Kind, e.Label, e.Status)
}

// ontologyProposalState reads back the current state for (kind, label), if
// this tenant's World has ever observed it. Read-locked, mirroring
// OntologyProposals' own locking, since ApproveOntologyExtension and
// RejectOntologyExtension must validate against current state before
// Submitting — the same pre-Submit validation pattern
// ProposeOntologyExtension uses for taxonomy.ValidIdentifier.
func (e *Engine) ontologyProposalState(kind taxonomy.ProposalKind, label string) (OntologyProposalState, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s, ok := e.World.ontologyProposals[ontologyProposalKey{kind: kind, label: label}]
	return s, ok
}

// ApproveOntologyExtension is the entry point the tenant-owner-gated
// OntologyExtensionService.ApproveOntologyExtensionProposal RPC calls
// (gibson#392, ADR-0033 decision 3): the tenant owner approves a
// previously-proposed Taxonomy node label or relationship type. It is the
// ONLY exported way an OntologyExtensionApproved event reaches this Engine's
// intake.
//
// label is checked against taxonomy.ValidIdentifier BEFORE Submit, mirroring
// ProposeOntologyExtension's own fail-closed check — redundant in practice
// (an invalid label could never have reached ontologyProposals in the first
// place), but independent defense in depth, exactly like
// taxonomy.PromotionGate.Confirm's own re-check. reviewer is required,
// mirroring ProposeOntologyExtension's proposer/claim requirement — an
// unattributed approval cannot be audited.
//
// Refuses with *OntologyProposalNotFoundError when no matching proposal has
// ever been observed, and with *OntologyProposalAlreadyDecidedError when
// (kind, label) already carries a terminal decision.
//
// Like ProposeOntologyExtension, the resulting event is folded asynchronously
// through the normal single-writer Submit path (ADR-0001): whether this
// approval actually promoted the extension (enough recurrence, not just
// approval) is visible only after the fold — read OntologyProposals()
// afterward, never assume Promoted the instant this call returns.
func (e *Engine) ApproveOntologyExtension(_ context.Context, kind taxonomy.ProposalKind, label, reviewer string) error {
	if err := taxonomy.ValidIdentifier(label); err != nil {
		return &taxonomy.InvalidProposalError{Kind: kind, Label: label, Err: err}
	}
	if reviewer == "" {
		return fmt.Errorf("brain: ontology extension approval for %s %q has no reviewer; an unattributed approval cannot be audited", kind, label)
	}
	state, ok := e.ontologyProposalState(kind, label)
	if !ok {
		return &OntologyProposalNotFoundError{Kind: kind, Label: label}
	}
	if state.Status != OntologyProposalPending {
		return &OntologyProposalAlreadyDecidedError{Kind: kind, Label: label, Status: state.Status}
	}
	e.Submit(OntologyExtensionApproved{
		ProposalKind: kind,
		Label:        label,
		Reviewer:     reviewer,
	})
	return nil
}

// RejectOntologyExtension is the entry point the tenant-owner-gated
// OntologyExtensionService.RejectOntologyExtensionProposal RPC calls
// (gibson#392, ADR-0033 decision 3): the tenant owner rejects a
// previously-proposed Taxonomy node label or relationship type. Same
// existence/terminal-decision/attribution checks as ApproveOntologyExtension;
// reason is optional (a rejection needs no rationale to take effect, unlike
// a proposal's Claim, which motivates review in the first place).
func (e *Engine) RejectOntologyExtension(_ context.Context, kind taxonomy.ProposalKind, label, reviewer, reason string) error {
	if err := taxonomy.ValidIdentifier(label); err != nil {
		return &taxonomy.InvalidProposalError{Kind: kind, Label: label, Err: err}
	}
	if reviewer == "" {
		return fmt.Errorf("brain: ontology extension rejection for %s %q has no reviewer; an unattributed rejection cannot be audited", kind, label)
	}
	state, ok := e.ontologyProposalState(kind, label)
	if !ok {
		return &OntologyProposalNotFoundError{Kind: kind, Label: label}
	}
	if state.Status != OntologyProposalPending {
		return &OntologyProposalAlreadyDecidedError{Kind: kind, Label: label, Status: state.Status}
	}
	e.Submit(OntologyExtensionRejected{
		ProposalKind: kind,
		Label:        label,
		Reviewer:     reviewer,
		Reason:       reason,
	})
	return nil
}
