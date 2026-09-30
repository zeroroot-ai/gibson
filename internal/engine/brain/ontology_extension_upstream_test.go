// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// promoteLabel drives a (kind, label) proposal all the way to a live tenant
// extension: taxonomy.MinRecurrenceForSettlement sightings plus one owner
// approval, mirroring TestApproveOntologyExtension_PromotesOnceSettled's own
// setup exactly.
func promoteLabel(t *testing.T, e *Engine, kind taxonomy.ProposalKind, label string) {
	t.Helper()
	proposeNTimes(t, e, kind, label, taxonomy.MinRecurrenceForSettlement)
	require.NoError(t, e.ApproveOntologyExtension(context.Background(), kind, label, "owner-1"))
	e.Tick()
}

func TestSubmitOntologyExtensionUpstream_NotFoundIsRefused(t *testing.T) {
	e := newTestEngine()
	_, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "Container")
	require.Error(t, err)
	var notFound *OntologyProposalNotFoundError
	require.ErrorAs(t, err, &notFound)
}

func TestSubmitOntologyExtensionUpstream_InvalidIdentifierIsRejectedFailClosed(t *testing.T) {
	e := newTestEngine()
	_, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "not a valid identifier!")
	require.Error(t, err)
	var invalid *taxonomy.InvalidProposalError
	require.ErrorAs(t, err, &invalid)
}

// TestSubmitOntologyExtensionUpstream_PendingProposalIsRefused proves
// ADR-0033 decision 3's "submit-upstream is available only from a live
// tenant extension": a proposal that has never even been approved is
// refused, distinct from OntologyProposalNotFoundError.
func TestSubmitOntologyExtensionUpstream_PendingProposalIsRefused(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)

	_, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "Container")
	require.Error(t, err)
	var notPromoted *OntologyProposalNotPromotedError
	require.ErrorAs(t, err, &notPromoted)
	assert.Equal(t, OntologyProposalPending, notPromoted.Status)
}

// TestSubmitOntologyExtensionUpstream_ApprovedButNotYetSettledIsRefused
// proves the same refusal holds for a proposal the owner has already
// approved but which has not yet recurred enough times to actually promote
// (Approved != Promoted, mirroring
// TestApproveOntologyExtension_NotYetSettledRecordsApprovalWithoutPromoting).
func TestSubmitOntologyExtensionUpstream_ApprovedButNotYetSettledIsRefused(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)
	require.NoError(t, e.ApproveOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1"))
	e.Tick()

	_, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "Container")
	require.Error(t, err)
	var notPromoted *OntologyProposalNotPromotedError
	require.ErrorAs(t, err, &notPromoted)
	assert.Equal(t, OntologyProposalApproved, notPromoted.Status)
}

// TestSubmitOntologyExtensionUpstream_RejectedProposalIsRefused proves a
// rejected proposal (never promoted, by construction) also refuses.
func TestSubmitOntologyExtensionUpstream_RejectedProposalIsRefused(t *testing.T) {
	e := newTestEngine()
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)
	require.NoError(t, e.RejectOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "owner-1", "no"))
	e.Tick()

	_, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "Container")
	require.Error(t, err)
	var notPromoted *OntologyProposalNotPromotedError
	require.ErrorAs(t, err, &notPromoted)
	assert.Equal(t, OntologyProposalRejected, notPromoted.Status)
}

// TestSubmitOntologyExtensionUpstream_RendersNodeLabelFragment proves the
// full gibson#393 acceptance path for a promoted node-label extension: the
// rendered pack carries exactly the promoted label, attributed to this
// tenant, and passes ontology.DomainPack's own Validate.
func TestSubmitOntologyExtensionUpstream_RendersNodeLabelFragment(t *testing.T) {
	e := NewEngine("acme")
	promoteLabel(t, e, taxonomy.ProposedNodeLabel, "Container")

	pack, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "Container")
	require.NoError(t, err)
	require.NotNil(t, pack)

	assert.Equal(t, "Container", pack.Name)
	assert.Equal(t, 1, pack.Version)
	assert.Equal(t, "acme", pack.Author)
	assert.Equal(t, []string{"Container"}, pack.TaxonomyNodeLabels)
	assert.Empty(t, pack.TaxonomyRelationshipTypes)
	assert.Empty(t, pack.Visibility, "a contribution candidate is not yet classified public/private")
	assert.Empty(t, pack.Entitlement)
	require.NoError(t, pack.Validate())
}

// TestSubmitOntologyExtensionUpstream_RendersRelationshipTypeFragment mirrors
// the node-label case for the other half of taxonomy's proposal vocabulary.
func TestSubmitOntologyExtensionUpstream_RendersRelationshipTypeFragment(t *testing.T) {
	e := NewEngine("acme")
	promoteLabel(t, e, taxonomy.ProposedRelationshipType, "RUNS_ON")

	pack, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedRelationshipType, "RUNS_ON")
	require.NoError(t, err)
	require.NotNil(t, pack)

	assert.Equal(t, "RUNS_ON", pack.Name)
	assert.Equal(t, []string{"RUNS_ON"}, pack.TaxonomyRelationshipTypes)
	assert.Empty(t, pack.TaxonomyNodeLabels)
	require.NoError(t, pack.Validate())
}

// TestSubmitOntologyExtensionUpstream_DoesNotMutateWorld proves this is a
// pure read (unlike Propose/Approve/Reject): it submits no event, so a
// second call renders byte-identical content and the proposal snapshot is
// unchanged.
func TestSubmitOntologyExtensionUpstream_DoesNotMutateWorld(t *testing.T) {
	e := NewEngine("acme")
	promoteLabel(t, e, taxonomy.ProposedNodeLabel, "Container")

	before := e.OntologyProposals()
	pack1, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "Container")
	require.NoError(t, err)
	pack2, err := e.SubmitOntologyExtensionUpstream(context.Background(), taxonomy.ProposedNodeLabel, "Container")
	require.NoError(t, err)
	e.Tick()
	after := e.OntologyProposals()

	assert.Equal(t, pack1, pack2)
	assert.Equal(t, before, after)
}

func TestOntologyProposalNotPromotedError_Error(t *testing.T) {
	err := &OntologyProposalNotPromotedError{Kind: taxonomy.ProposedNodeLabel, Label: "Container", Status: OntologyProposalPending}
	assert.Contains(t, err.Error(), "Container")
	assert.Contains(t, err.Error(), "not yet a live tenant extension")
}
