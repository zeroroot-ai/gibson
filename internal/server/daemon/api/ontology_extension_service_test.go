// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// newOntologyExtensionService builds an OntologyExtensionService over a
// fresh brain.Registry, mirroring newDomainPackService.
func newOntologyExtensionService(t *testing.T) (*OntologyExtensionService, *brain.Registry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx)
	return NewOntologyExtensionService(reg), reg
}

// ownerCtx builds a context carrying both the tenant and the acting user —
// what ApproveOntologyExtensionProposal/RejectOntologyExtensionProposal need
// to attribute a decision (the FGA "owner" relation check itself happens in
// ext-authz, never in this handler — see registry_test's ownership_relations_test.go
// for that contract's own pinned test).
func ownerCtx(tenantID, userID string) context.Context {
	return auth.ContextWithActingUser(tenantCtx(tenantID), userID)
}

// proposeNTimes submits label to e's tenant via ProposeOntologyExtension n
// times and ticks the engine, driving recurrence to exactly n.
func proposeNTimes(t *testing.T, e *brain.Engine, kind taxonomy.ProposalKind, label string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, e.ProposeOntologyExtension(context.Background(), kind, label, "agent-1", "sighted it"))
	}
	e.Tick()
}

// waitForOntologyProposal polls ListOntologyExtensionProposals until it sees
// a proposal for label whose Status is at least decided, or the deadline
// passes — ApproveOntologyExtensionProposal/RejectOntologyExtensionProposal
// submit asynchronously (ADR-0001), mirroring awaitPending /
// waitForDomainPacks.
func waitForOntologyProposal(ctx context.Context, t *testing.T, s *OntologyExtensionService, label string, wantStatus tenantv1.OntologyProposalStatus) *tenantv1.OntologyExtensionProposal {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := s.ListOntologyExtensionProposals(ctx, &tenantv1.ListOntologyExtensionProposalsRequest{})
		require.NoError(t, err)
		for _, p := range resp.GetProposals() {
			if p.GetLabel() == label && p.GetStatus() == wantStatus {
				return p
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proposal %q never reached status %v", label, wantStatus)
	return nil
}

// -----------------------------------------------------------------------
// Conversion helpers and error mapping (table-driven, direct unit coverage)
// -----------------------------------------------------------------------

func TestOntologyProposalKind_UnrecognizedValueIsRejected(t *testing.T) {
	_, err := ontologyProposalKind(tenantv1.OntologyProposalKind(99))
	require.Error(t, err)
}

func TestOntologyProposalKind_UnspecifiedIsRejected(t *testing.T) {
	_, err := ontologyProposalKind(tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_UNSPECIFIED)
	require.Error(t, err)
}

func TestOntologyProposalKind_RoundTripsBothVocabularies(t *testing.T) {
	nodeLabel, err := ontologyProposalKind(tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL)
	require.NoError(t, err)
	assert.Equal(t, taxonomy.ProposedNodeLabel, nodeLabel)

	relType, err := ontologyProposalKind(tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE)
	require.NoError(t, err)
	assert.Equal(t, taxonomy.ProposedRelationshipType, relType)

	assert.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, ontologyProposalKindPB(taxonomy.ProposedNodeLabel))
	assert.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE, ontologyProposalKindPB(taxonomy.ProposedRelationshipType))
}

func TestOntologyProposalKindPB_UnrecognizedValueIsUnspecified(t *testing.T) {
	assert.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_UNSPECIFIED, ontologyProposalKindPB(taxonomy.ProposalKind(99)))
}

func TestOntologyProposalStatusPB_UnrecognizedValueIsUnspecified(t *testing.T) {
	assert.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_UNSPECIFIED, ontologyProposalStatusPB(brain.OntologyProposalStatus(99)))
}

func TestOntologyDecisionError_MapsEachErrorKind(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not found", &brain.OntologyProposalNotFoundError{Kind: taxonomy.ProposedNodeLabel, Label: "Container"}, codes.NotFound},
		{"already decided", &brain.OntologyProposalAlreadyDecidedError{Kind: taxonomy.ProposedNodeLabel, Label: "Container", Status: brain.OntologyProposalApproved}, codes.FailedPrecondition},
		{"invalid identifier", &taxonomy.InvalidProposalError{Kind: taxonomy.ProposedNodeLabel, Label: "!bad", Err: assert.AnError}, codes.InvalidArgument},
		{"anything else", assert.AnError, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, status.Code(ontologyDecisionError("Test", tt.err)))
		})
	}
}

// -----------------------------------------------------------------------
// ListOntologyExtensionProposals
// -----------------------------------------------------------------------

func TestListOntologyExtensionProposals_MissingTenantIsDenied(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.ListOntologyExtensionProposals(context.Background(), &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListOntologyExtensionProposals_OtherTenantIsInvisible(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	resp, err := s.ListOntologyExtensionProposals(tenantCtx("umbrella"), &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetProposals())
}

func TestListOntologyExtensionProposals_ReturnsRecurrenceAndAttribution(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 2)

	resp, err := s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetProposals(), 1)
	p := resp.GetProposals()[0]
	assert.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, p.GetKind())
	assert.Equal(t, "Container", p.GetLabel())
	assert.Equal(t, int32(2), p.GetRecurrence())
	assert.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_PENDING, p.GetStatus())
	assert.False(t, p.GetPromoted())
}

// -----------------------------------------------------------------------
// ApproveOntologyExtensionProposal
// -----------------------------------------------------------------------

func TestApproveOntologyExtensionProposal_MissingTenantIsDenied(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.ApproveOntologyExtensionProposal(context.Background(), &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestApproveOntologyExtensionProposal_MissingActingUserIsUnauthenticated(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	_, err := s.ApproveOntologyExtensionProposal(tenantCtx("acme"), &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestApproveOntologyExtensionProposal_UnspecifiedKindIsInvalidArgument(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	_, err := s.ApproveOntologyExtensionProposal(ownerCtx("acme", "owner-1"), &tenantv1.ApproveOntologyExtensionProposalRequest{
		Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestApproveOntologyExtensionProposal_EmptyLabelIsInvalidArgument(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.ApproveOntologyExtensionProposal(ownerCtx("acme", "owner-1"), &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestApproveOntologyExtensionProposal_NotFoundIsNotFound(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.ApproveOntologyExtensionProposal(ownerCtx("acme", "owner-1"), &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestApproveOntologyExtensionProposal_PromotesOnceSettled is the full
// gibson#392 acceptance path exercised through the gRPC-shaped handler: a
// proposal that has already recurred taxonomy.MinRecurrenceForSettlement
// times is promoted into a live, per-tenant taxonomy extension the moment
// the owner approves it.
func TestApproveOntologyExtensionProposal_PromotesOnceSettled(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement)

	ctx := ownerCtx("acme", "owner-1")
	_, err := s.ApproveOntologyExtensionProposal(ctx, &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.NoError(t, err)

	p := waitForOntologyProposal(ctx, t, s, "Container", tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_APPROVED)
	assert.Equal(t, "owner-1", p.GetReviewer())
	// Promoted is the authoritative "is this a live tenant extension yet"
	// signal (ADR-0033) — the brain package's own tests
	// (TestApproveOntologyExtension_PromotesOnceSettled) verify this maps to
	// an actual admitted taxonomy.Registry label; this RPC-level test proves
	// the signal reaches the wire.
	assert.True(t, p.GetPromoted(), "settlement is complete (recurrence + approval); the extension must be live")
	assert.Positive(t, p.GetPromotedTaxonomyVersion())
}

// TestApproveOntologyExtensionProposal_AlreadyDecidedIsFailedPrecondition
// proves the owner's decision is terminal through this RPC surface too.
func TestApproveOntologyExtensionProposal_AlreadyDecidedIsFailedPrecondition(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement)

	ctx := ownerCtx("acme", "owner-1")
	req := &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	}
	_, err := s.ApproveOntologyExtensionProposal(ctx, req)
	require.NoError(t, err)
	waitForOntologyProposal(ctx, t, s, "Container", tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_APPROVED)

	_, err = s.ApproveOntologyExtensionProposal(ctx, req)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// -----------------------------------------------------------------------
// RejectOntologyExtensionProposal
// -----------------------------------------------------------------------

func TestRejectOntologyExtensionProposal_UnspecifiedKindIsInvalidArgument(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	_, err := s.RejectOntologyExtensionProposal(ownerCtx("acme", "owner-1"), &tenantv1.RejectOntologyExtensionProposalRequest{
		Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRejectOntologyExtensionProposal_EmptyLabelIsInvalidArgument(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.RejectOntologyExtensionProposal(ownerCtx("acme", "owner-1"), &tenantv1.RejectOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRejectOntologyExtensionProposal_MissingTenantIsDenied(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.RejectOntologyExtensionProposal(context.Background(), &tenantv1.RejectOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRejectOntologyExtensionProposal_MissingActingUserIsUnauthenticated(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	_, err := s.RejectOntologyExtensionProposal(tenantCtx("acme"), &tenantv1.RejectOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRejectOntologyExtensionProposal_NotFoundIsNotFound(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.RejectOntologyExtensionProposal(ownerCtx("acme", "owner-1"), &tenantv1.RejectOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestRejectOntologyExtensionProposal_RecordsRejectionAndNeverPromotes proves
// rejection is a real, non-bypassable refusal through this RPC surface: the
// proposal never promotes even after it recurs enough times afterward.
func TestRejectOntologyExtensionProposal_RecordsRejectionAndNeverPromotes(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	e := reg.For("acme")
	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", 1)

	ctx := ownerCtx("acme", "owner-1")
	_, err := s.RejectOntologyExtensionProposal(ctx, &tenantv1.RejectOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container", Reason: "not needed",
	})
	require.NoError(t, err)

	p := waitForOntologyProposal(ctx, t, s, "Container", tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_REJECTED)
	assert.Equal(t, "owner-1", p.GetReviewer())
	assert.Equal(t, "not needed", p.GetRejectReason())
	assert.False(t, p.GetPromoted())

	proposeNTimes(t, e, taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement+2)
	resp, err := s.ListOntologyExtensionProposals(ctx, &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetProposals(), 1)
	assert.False(t, resp.GetProposals()[0].GetPromoted())
}
