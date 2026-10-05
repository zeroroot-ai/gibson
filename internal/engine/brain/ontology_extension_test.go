// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// TestOntologyExtensionProposed_CodecRoundTrip proves OntologyExtensionProposed
// survives the durable Timeline's JSON envelope round trip (EncodeEvent/
// DecodeEvent) — required for durable persistence (ADR-0163) and for the
// codec's kind registry to stay complete, mirroring
// TestDomainPackEvents_CodecRoundTrip.
func TestOntologyExtensionProposed_CodecRoundTrip(t *testing.T) {
	ev := OntologyExtensionProposed{
		ProposalKind: taxonomy.ProposedRelationshipType,
		Label:        "RUNS_ON",
		Proposer:     "agent-1",
		Claim:        "sighted an edge worth naming",
	}
	b, err := EncodeEvent(ev)
	require.NoError(t, err)
	decoded, err := DecodeEvent(b)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(decoded, Event(ev)), "round trip: got %#v (%T), want %#v", decoded, decoded, ev)
}

// TestOntologyExtensionProposed_ReplayReproducesTheWorld is the core
// gibson#391 determinism unit: World == fold(Timeline) for proposal
// recurrence, mirroring TestDomainPack_EnableDisable_ReplayReproducesTheWorld.
func TestOntologyExtensionProposed_ReplayReproducesTheWorld(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("tenant-1")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-1", Claim: "sighted a container node"})
	apply(OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-2", Claim: "sighted it again"})
	apply(OntologyExtensionProposed{ProposalKind: taxonomy.ProposedRelationshipType, Label: "RUNS_ON", Proposer: "agent-1", Claim: "sighted an edge"})

	want := w.OntologyProposalSnapshot()
	require.Len(t, want, 2)

	replayed := Replay("tenant-1", tl)
	assert.Equal(t, want, replayed.OntologyProposalSnapshot())
}

// TestOntologyExtensionProposed_RecurrenceIsCounted proves PromotionGate.
// Observe's recurrence counting is wired end to end: the SAME (kind, label)
// sighted three times reports recurrence 3, and DIFFERENT labels never share
// a counter.
func TestOntologyExtensionProposed_RecurrenceIsCounted(t *testing.T) {
	w := NewWorld("tenant-1")

	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-1", Claim: "one"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-2", Claim: "two"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-3", Claim: "three"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Sidecar", Proposer: "agent-1", Claim: "unrelated"})

	snapshot := w.OntologyProposalSnapshot()
	require.Len(t, snapshot, 2)

	byLabel := make(map[string]OntologyProposalSnapshot, len(snapshot))
	for _, s := range snapshot {
		byLabel[s.Label] = s
	}

	require.Contains(t, byLabel, "Container")
	assert.Equal(t, 3, byLabel["Container"].Recurrence)
	assert.Equal(t, "agent-3", byLabel["Container"].LastProposer)
	assert.Equal(t, "three", byLabel["Container"].LastClaim)

	require.Contains(t, byLabel, "Sidecar")
	assert.Equal(t, 1, byLabel["Sidecar"].Recurrence)
}

// TestOntologyExtensionProposed_NodeLabelAndRelationshipTypeAreDistinctCounters
// proves the two ProposalKind vocabularies never share a recurrence counter,
// even for the identical label text (taxonomy's own proposalKey includes
// kind).
func TestOntologyExtensionProposed_NodeLabelAndRelationshipTypeAreDistinctCounters(t *testing.T) {
	w := NewWorld("tenant-1")

	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Runs", Proposer: "agent-1", Claim: "as a node label"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedRelationshipType, Label: "Runs", Proposer: "agent-1", Claim: "as a relationship type"})

	snapshot := w.OntologyProposalSnapshot()
	require.Len(t, snapshot, 2)
	for _, s := range snapshot {
		assert.Equal(t, 1, s.Recurrence, "each kind's first sighting of %q must count separately", s.Label)
	}
}

// TestOntologyExtensionProposed_IsPerTenant proves proposal recurrence is
// structurally per-tenant (ADR-0133): proposing in one tenant's
// World never affects another's, mirroring TestDomainPack_Enable_IsPerTenant.
func TestOntologyExtensionProposed_IsPerTenant(t *testing.T) {
	acme := NewWorld("acme")
	other := NewWorld("other")

	Reduce(acme, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-1", Claim: "acme sighting"})

	assert.Len(t, acme.OntologyProposalSnapshot(), 1)
	assert.Empty(t, other.OntologyProposalSnapshot())
}

// -----------------------------------------------------------------------
// Engine.ProposeOntologyExtension: the ValidIdentifier safety gate.
// -----------------------------------------------------------------------

// newTestEngine returns an Engine with no Run loop started: tests drive
// folding explicitly via e.Tick() so assertions never race a background
// ticker.
func newTestEngine() *Engine {
	return NewEngine("tenant-1")
}

func TestProposeOntologyExtension_InvalidIdentifierIsRejectedFailClosed(t *testing.T) {
	e := newTestEngine()

	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "not a valid identifier!", "agent-1", "a claim")
	require.Error(t, err)

	var invalid *taxonomy.InvalidProposalError
	require.ErrorAs(t, err, &invalid)

	// Rejected fail-closed: nothing was ever Submitted, so a Tick folds
	// nothing and no recurrence accumulates for the rejected label.
	e.Tick()
	assert.Empty(t, e.OntologyProposals())
}

func TestProposeOntologyExtension_EmptyLabelIsRejected(t *testing.T) {
	e := newTestEngine()
	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "", "agent-1", "a claim")
	require.Error(t, err)
	var invalid *taxonomy.InvalidProposalError
	assert.ErrorAs(t, err, &invalid)
}

func TestProposeOntologyExtension_RequiresProposer(t *testing.T) {
	e := newTestEngine()
	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "", "a claim")
	require.Error(t, err)
}

func TestProposeOntologyExtension_RequiresClaim(t *testing.T) {
	e := newTestEngine()
	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-1", "")
	require.Error(t, err)
}

// TestProposeOntologyExtension_ValidProposalIsObservedAndCounted proves a
// valid proposal reaches the Timeline, folds, and is counted — the full
// gibson#391 acceptance path exercised through the exported Engine seam
// rather than Reduce directly.
func TestProposeOntologyExtension_ValidProposalIsObservedAndCounted(t *testing.T) {
	e := newTestEngine()

	require.NoError(t, e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-1", "sighted a container node"))
	require.NoError(t, e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-2", "sighted it again"))
	e.Tick()

	snapshot := e.OntologyProposals()
	require.Len(t, snapshot, 1)
	assert.Equal(t, "Container", snapshot[0].Label)
	assert.Equal(t, taxonomy.ProposedNodeLabel, snapshot[0].ProposalKind)
	assert.Equal(t, 2, snapshot[0].Recurrence)
	assert.Equal(t, "agent-2", snapshot[0].LastProposer)
}

// TestOntologyDiscoveryEngine_EngineSatisfiesTheSeam is a compile-time-style
// proof, run at test time, that *Engine really does satisfy the interface a
// future RPC handler will be written against (gibson#391), mirroring
// belief_world_substrate_test's equivalent assertion pattern for
// BeliefSubstrate.
func TestOntologyDiscoveryEngine_EngineSatisfiesTheSeam(t *testing.T) {
	var seam OntologyDiscoveryEngine = NewEngine("tenant-1")
	err := seam.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-1", "a claim")
	require.NoError(t, err)
}

// -----------------------------------------------------------------------
// Engine.ApproveOntologyExtension / RejectOntologyExtension (gibson#392,
// ADR-0133): the tenant-owner approval flow.
// -----------------------------------------------------------------------

// proposeNTimes submits label n times through ProposeOntologyExtension and
// ticks the engine, driving recurrence to exactly n.
func proposeNTimes(t *testing.T, e *Engine, kind taxonomy.ProposalKind, label string, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, e.ProposeOntologyExtension(context.Background(), kind, label, fmt.Sprintf("agent-%d", i), "sighted it"))
	}
	e.Tick()
}

func TestApproveOntologyExtension_NotFoundIsRefused(t *testing.T) {
	e := newTestEngine()
	err := e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1")
	require.Error(t, err)
	var notFound *OntologyProposalNotFoundError
	require.ErrorAs(t, err, &notFound)
}

func TestRejectOntologyExtension_NotFoundIsRefused(t *testing.T) {
	e := newTestEngine()
	err := e.RejectOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1", "no thanks")
	require.Error(t, err)
	var notFound *OntologyProposalNotFoundError
	require.ErrorAs(t, err, &notFound)
}

func TestApproveOntologyExtension_RequiresReviewer(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)
	err := e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "")
	require.Error(t, err)
}

func TestRejectOntologyExtension_RequiresReviewer(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)
	err := e.RejectOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "", "reason")
	require.Error(t, err)
}

func TestApproveOntologyExtension_InvalidIdentifierIsRejectedFailClosed(t *testing.T) {
	e := newTestEngine()
	err := e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "not a valid identifier!", "owner-1")
	require.Error(t, err)
	var invalid *taxonomy.InvalidProposalError
	require.ErrorAs(t, err, &invalid)
}

// TestApproveOntologyExtension_PromotesOnceSettled proves the full gibson#392
// acceptance path: a proposal that has ALREADY recurred
// taxonomy.MinRecurrenceForSettlement times is promoted into a live,
// per-tenant taxonomy extension the instant the owner approves it.
func TestApproveOntologyExtension_PromotesOnceSettled(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement)

	require.NoError(t, e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1"))
	e.Tick()

	snapshot := e.OntologyProposals()
	require.Len(t, snapshot, 1)
	assert.Equal(t, OntologyProposalApproved, snapshot[0].Status)
	assert.Equal(t, "owner-1", snapshot[0].Reviewer)
	assert.True(t, snapshot[0].Promoted, "settlement is complete (recurrence + approval); the extension must be live")
	assert.Positive(t, snapshot[0].PromotedVersion)

	// The live effect: the tenant's own taxonomy registry now admits the
	// promoted label — this IS "a live tenant extension" (ADR-0133).
	assert.Contains(t, e.World.ontologyGate.Base().NodeLabels(), "Container")
}

// TestApproveOntologyExtension_NotYetSettledRecordsApprovalWithoutPromoting
// proves approving BEFORE enough recurrence records the owner's decision
// without promoting — and that a later sighting completes promotion without
// requiring the owner to approve twice (settlement is symmetric in its two
// halves, ADR-0133).
func TestApproveOntologyExtension_NotYetSettledRecordsApprovalWithoutPromoting(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)

	require.NoError(t, e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1"))
	e.Tick()

	snapshot := e.OntologyProposals()
	require.Len(t, snapshot, 1)
	assert.Equal(t, OntologyProposalApproved, snapshot[0].Status)
	assert.False(t, snapshot[0].Promoted, "recurrence has not met MinRecurrenceForSettlement yet")
	assert.NotContains(t, e.World.ontologyGate.Base().NodeLabels(), "Container")

	// A later sighting pushes recurrence to MinRecurrenceForSettlement.
	// Promotion completes automatically — no second approval needed.
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement-1)

	snapshot = e.OntologyProposals()
	require.Len(t, snapshot, 1)
	assert.True(t, snapshot[0].Promoted)
	assert.Contains(t, e.World.ontologyGate.Base().NodeLabels(), "Container")
}

// TestApproveOntologyExtension_AlreadyDecidedIsRefused proves the owner's
// decision is terminal: approving (or rejecting) an already-decided proposal
// is refused rather than silently overwriting the first decision.
func TestApproveOntologyExtension_AlreadyDecidedIsRefused(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement)
	require.NoError(t, e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1"))
	e.Tick()

	err := e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1")
	require.Error(t, err)
	var decided *OntologyProposalAlreadyDecidedError
	require.ErrorAs(t, err, &decided)

	err = e.RejectOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1", "changed my mind")
	require.Error(t, err)
	require.ErrorAs(t, err, &decided)
}

// TestRejectOntologyExtension_NeverPromotesEvenAfterMoreRecurrence proves
// rejection is a real, non-bypassable refusal: further sightings of the SAME
// (kind, label) after a rejection still never promote it, because Confirm
// (the HITL half) was never recorded.
func TestRejectOntologyExtension_NeverPromotesEvenAfterMoreRecurrence(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)

	require.NoError(t, e.RejectOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1", "not needed"))
	e.Tick()

	snapshot := e.OntologyProposals()
	require.Len(t, snapshot, 1)
	assert.Equal(t, OntologyProposalRejected, snapshot[0].Status)
	assert.Equal(t, "owner-1", snapshot[0].Reviewer)
	assert.Equal(t, "not needed", snapshot[0].RejectReason)

	// Even sighting it MinRecurrenceForSettlement more times never promotes it.
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement+2)

	snapshot = e.OntologyProposals()
	require.Len(t, snapshot, 1)
	assert.Equal(t, OntologyProposalRejected, snapshot[0].Status)
	assert.False(t, snapshot[0].Promoted)
	assert.NotContains(t, e.World.ontologyGate.Base().NodeLabels(), "Container")
}

// TestOntologyExtensionApproved_CodecRoundTrip and
// TestOntologyExtensionRejected_CodecRoundTrip prove the two new events
// survive the durable Timeline's JSON envelope round trip, mirroring
// TestOntologyExtensionProposed_CodecRoundTrip.
func TestOntologyExtensionApproved_CodecRoundTrip(t *testing.T) {
	ev := OntologyExtensionApproved{
		ProposalKind: taxonomy.ProposedNodeLabel,
		Label:        "Container",
		Reviewer:     "owner-1",
	}
	b, err := EncodeEvent(ev)
	require.NoError(t, err)
	decoded, err := DecodeEvent(b)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(decoded, Event(ev)), "round trip: got %#v (%T), want %#v", decoded, decoded, ev)
}

func TestOntologyExtensionRejected_CodecRoundTrip(t *testing.T) {
	ev := OntologyExtensionRejected{
		ProposalKind: taxonomy.ProposedRelationshipType,
		Label:        "RUNS_ON",
		Reviewer:     "owner-1",
		Reason:       "too niche",
	}
	b, err := EncodeEvent(ev)
	require.NoError(t, err)
	decoded, err := DecodeEvent(b)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(decoded, Event(ev)), "round trip: got %#v (%T), want %#v", decoded, decoded, ev)
}

func TestOntologyProposalStatus_String(t *testing.T) {
	assert.Equal(t, "pending", OntologyProposalPending.String())
	assert.Equal(t, "approved", OntologyProposalApproved.String())
	assert.Equal(t, "rejected", OntologyProposalRejected.String())
	assert.Equal(t, "unknown", OntologyProposalStatus(99).String())
}

// TestApplyOntologyExtensionApproved_NoMatchingProposalIsANoOp proves the
// fold stays defined (never panics) for an OntologyExtensionApproved that
// names no proposal this tenant's World has ever observed — a defensive
// branch that cannot occur via the Engine seam (which checks existence
// before Submit), exercised directly through Reduce for replay-robustness.
func TestApplyOntologyExtensionApproved_NoMatchingProposalIsANoOp(t *testing.T) {
	w := NewWorld("tenant-1")
	Reduce(w, OntologyExtensionApproved{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Reviewer: "owner-1"})
	assert.Empty(t, w.OntologyProposalSnapshot())
}

// TestApplyOntologyExtensionApproved_ConfirmFailureIsANoOp proves the fold's
// Confirm-error branch is defensive, not reachable via the Engine seam
// (which checks taxonomy.ValidIdentifier before Submit), by planting an
// invalid-identifier proposal directly through Reduce (bypassing the Engine
// gate entirely, as Replay itself would).
func TestApplyOntologyExtensionApproved_ConfirmFailureIsANoOp(t *testing.T) {
	w := NewWorld("tenant-1")
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "not valid!", Proposer: "agent-1", Claim: "c"})
	Reduce(w, OntologyExtensionApproved{ProposalKind: taxonomy.ProposedNodeLabel, Label: "not valid!", Reviewer: "owner-1"})

	snapshot := w.OntologyProposalSnapshot()
	require.Len(t, snapshot, 1)
	assert.Equal(t, OntologyProposalPending, snapshot[0].Status, "Confirm's ValidIdentifier failure must leave the proposal Pending, not silently Approved")
}

// TestApplyOntologyExtensionRejected_NoMatchingProposalIsANoOp mirrors
// TestApplyOntologyExtensionApproved_NoMatchingProposalIsANoOp for rejection.
func TestApplyOntologyExtensionRejected_NoMatchingProposalIsANoOp(t *testing.T) {
	w := NewWorld("tenant-1")
	Reduce(w, OntologyExtensionRejected{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Reviewer: "owner-1", Reason: "no"})
	assert.Empty(t, w.OntologyProposalSnapshot())
}

func TestRejectOntologyExtension_InvalidIdentifierIsRejectedFailClosed(t *testing.T) {
	e := newTestEngine()
	err := e.RejectOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "not a valid identifier!", "owner-1", "reason")
	require.Error(t, err)
	var invalid *taxonomy.InvalidProposalError
	require.ErrorAs(t, err, &invalid)
}

// TestOntologyExtensionApproved_ReplayReproducesTheWorld is the gibson#392
// determinism unit, mirroring TestOntologyExtensionProposed_ReplayReproducesTheWorld:
// World == fold(Timeline) for the approval/promotion outcome too.
func TestOntologyExtensionApproved_ReplayReproducesTheWorld(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("tenant-1")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	for range taxonomy.MinRecurrenceForSettlement {
		apply(OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-1", Claim: "sighted"})
	}
	apply(OntologyExtensionApproved{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Reviewer: "owner-1"})

	want := w.OntologyProposalSnapshot()
	require.Len(t, want, 1)
	require.True(t, want[0].Promoted)

	replayed := Replay("tenant-1", tl)
	assert.Equal(t, want, replayed.OntologyProposalSnapshot())
	assert.Equal(t, w.ontologyGate.Base().NodeLabels(), replayed.ontologyGate.Base().NodeLabels())
}
