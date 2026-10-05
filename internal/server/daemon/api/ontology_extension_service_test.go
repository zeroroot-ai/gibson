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
func proposeNTimes(ctx context.Context, t *testing.T, e *brain.Engine, kind taxonomy.ProposalKind, label string, n int) {
	t.Helper()
	for range n {
		require.NoError(t, e.ProposeOntologyExtension(ctx, kind, label, "agent-1", "sighted it"))
	}
	e.Tick() //nolint:contextcheck // Tick() is the engine's context-free synchronous drain; it takes no per-call context by design
}

// waitForOntologyProposal polls the tenant engine's proposal snapshot until
// it sees a proposal for label whose Status is wantStatus, or the deadline
// passes. ApproveOntologyExtensionProposal/RejectOntologyExtensionProposal
// submit asynchronously (ADR-0101), so the decided state lands on the next
// fold. The RPC list carries no proposals (gibson#502), so the engine is the
// observable.
func waitForOntologyProposal(t *testing.T, e *brain.Engine, label string, wantStatus brain.OntologyProposalStatus) brain.OntologyProposalSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range e.OntologyProposals() {
			if p.Label == label && p.Status == wantStatus {
				return p
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proposal %q never reached status %v", label, wantStatus)
	return brain.OntologyProposalSnapshot{}
}

// ontologyProposalKindPB is the test-side inverse of ontologyProposalKind.
func ontologyProposalKindPB(k taxonomy.ProposalKind) tenantv1.OntologyProposalKind {
	switch k {
	case taxonomy.ProposedNodeLabel:
		return tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL
	case taxonomy.ProposedRelationshipType:
		return tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE
	default:
		return tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_UNSPECIFIED
	}
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

}

func TestOntologyDecisionError_MapsEachErrorKind(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"not found", &brain.OntologyProposalNotFoundError{Kind: taxonomy.ProposedNodeLabel, Label: "Container"}, codes.NotFound},
		{"already decided", &brain.OntologyProposalAlreadyDecidedError{Kind: taxonomy.ProposedNodeLabel, Label: "Container", Status: brain.OntologyProposalApproved}, codes.FailedPrecondition},
		{"not promoted", &brain.OntologyProposalNotPromotedError{Kind: taxonomy.ProposedNodeLabel, Label: "Container", Status: brain.OntologyProposalPending}, codes.FailedPrecondition},
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

// TestListOntologyExtensionProposals_ReturnsAnEmptyListForATenant proves the
// RPC path reaches the tenant engine and answers: the response carries no
// proposals (gibson#502, gibson#618), and a tenant with proposals in its
// engine still gets an empty answer rather than an error.
func TestListOntologyExtensionProposals_ReturnsAnEmptyListForATenant(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	resp, err := s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, reg.For("acme").OntologyProposals(), 1, "the engine holds the proposal the RPC does not carry")
}

func TestListOntologyExtensionProposals_MissingTenantIsDenied(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.ListOntologyExtensionProposals(context.Background(), &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
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
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	_, err := s.ApproveOntologyExtensionProposal(tenantCtx("acme"), &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestApproveOntologyExtensionProposal_UnspecifiedKindIsInvalidArgument(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

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
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement)

	ctx := ownerCtx("acme", "owner-1")
	_, err := s.ApproveOntologyExtensionProposal(ctx, &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.NoError(t, err)

	p := waitForOntologyProposal(t, reg.For("acme"), "Container", brain.OntologyProposalApproved)
	assert.Equal(t, "owner-1", p.Reviewer)
	// Promoted is the authoritative "is this a live tenant extension yet"
	// signal (ADR-0133) — the brain package's own tests
	// (TestApproveOntologyExtension_PromotesOnceSettled) verify this maps to
	// an actual admitted taxonomy.Registry label; this RPC-level test proves
	// the signal reaches the wire.
	assert.True(t, p.Promoted, "settlement is complete (recurrence + approval); the extension must be live")
	assert.Positive(t, p.PromotedVersion)
}

// TestApproveOntologyExtensionProposal_AlreadyDecidedIsFailedPrecondition
// proves the owner's decision is terminal through this RPC surface too.
func TestApproveOntologyExtensionProposal_AlreadyDecidedIsFailedPrecondition(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement)

	ctx := ownerCtx("acme", "owner-1")
	req := &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	}
	_, err := s.ApproveOntologyExtensionProposal(ctx, req)
	require.NoError(t, err)
	waitForOntologyProposal(t, reg.For("acme"), "Container", brain.OntologyProposalApproved)

	_, err = s.ApproveOntologyExtensionProposal(ctx, req)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// -----------------------------------------------------------------------
// RejectOntologyExtensionProposal
// -----------------------------------------------------------------------

func TestRejectOntologyExtensionProposal_UnspecifiedKindIsInvalidArgument(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

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
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

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
	proposeNTimes(context.Background(), t, e, taxonomy.ProposedNodeLabel, "Container", 1)

	ctx := ownerCtx("acme", "owner-1")
	_, err := s.RejectOntologyExtensionProposal(ctx, &tenantv1.RejectOntologyExtensionProposalRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container", Reason: "not needed",
	})
	require.NoError(t, err)

	p := waitForOntologyProposal(t, e, "Container", brain.OntologyProposalRejected)
	assert.Equal(t, "owner-1", p.Reviewer)
	assert.Equal(t, "not needed", p.RejectReason)
	assert.False(t, p.Promoted)

	proposeNTimes(context.Background(), t, e, taxonomy.ProposedNodeLabel, "Container", taxonomy.MinRecurrenceForSettlement+2)
	snap := e.OntologyProposals()
	require.Len(t, snap, 1)
	assert.False(t, snap[0].Promoted)
}

// -----------------------------------------------------------------------
// SubmitOntologyExtensionUpstream (gibson#393, ADR-0133)
// -----------------------------------------------------------------------

// promoteViaRPC drives (kind, label) to a live tenant extension entirely
// through the RPC surface: taxonomy.MinRecurrenceForSettlement sightings
// plus one owner approval, then waits for the promoted read to land —
// mirrors TestApproveOntologyExtensionProposal_PromotesOnceSettled's own
// setup.
func promoteViaRPC(ctx context.Context, t *testing.T, s *OntologyExtensionService, reg *brain.Registry, tenantID string, kind taxonomy.ProposalKind, label string) {
	t.Helper()
	proposeNTimes(ctx, t, reg.For(tenantID), kind, label, taxonomy.MinRecurrenceForSettlement)
	_, err := s.ApproveOntologyExtensionProposal(ctx, &tenantv1.ApproveOntologyExtensionProposalRequest{
		Kind: ontologyProposalKindPB(kind), Label: label,
	})
	require.NoError(t, err)
	waitForOntologyProposal(t, reg.For(tenantID), label, brain.OntologyProposalApproved)
}

func TestSubmitOntologyExtensionUpstream_MissingTenantIsDenied(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.SubmitOntologyExtensionUpstream(context.Background(), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestSubmitOntologyExtensionUpstream_UnspecifiedKindIsInvalidArgument(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.SubmitOntologyExtensionUpstream(tenantCtx("acme"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSubmitOntologyExtensionUpstream_EmptyLabelIsInvalidArgument(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.SubmitOntologyExtensionUpstream(tenantCtx("acme"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSubmitOntologyExtensionUpstream_NotFoundIsNotFound(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	_, err := s.SubmitOntologyExtensionUpstream(tenantCtx("acme"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestSubmitOntologyExtensionUpstream_PendingProposalIsFailedPrecondition
// proves ADR-0133's "available only from a live tenant
// extension" through this RPC surface: a merely-observed, never-approved
// proposal is refused.
func TestSubmitOntologyExtensionUpstream_PendingProposalIsFailedPrecondition(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 1)

	_, err := s.SubmitOntologyExtensionUpstream(tenantCtx("acme"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestSubmitOntologyExtensionUpstream_OtherTenantsExtensionIsInvisible proves
// cross-tenant isolation holds for this RPC too: a proposal promoted in one
// tenant is invisible (NotFound, never leaked as content) from another.
func TestSubmitOntologyExtensionUpstream_OtherTenantsExtensionIsInvisible(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	promoteViaRPC(ownerCtx("acme", "owner-1"), t, s, reg, "acme", taxonomy.ProposedNodeLabel, "Container")

	_, err := s.SubmitOntologyExtensionUpstream(tenantCtx("umbrella"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestSubmitOntologyExtensionUpstream_AcceptsAPromotedExtension is the
// gibson#393 path through the RPC surface: a live tenant extension submits.
func TestSubmitOntologyExtensionUpstream_AcceptsAPromotedExtension(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	ctx := ownerCtx("acme", "owner-1")
	promoteViaRPC(ctx, t, s, reg, "acme", taxonomy.ProposedNodeLabel, "Container")

	resp, err := s.SubmitOntologyExtensionUpstream(tenantCtx("acme"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The response carries no artifact (gibson#502): the rendered pack is
	// covered by the brain package (ontology_extension_upstream_test.go). This
	// test proves the RPC path accepts a promoted extension.
}
