// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestListOntologyExtensionProposals_ReturnsEachProposal proves the list
// carries every field the dashboard review page reads (gibson#618).
func TestListOntologyExtensionProposals_ReturnsEachProposal(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	proposeNTimes(context.Background(), t, reg.For("acme"), taxonomy.ProposedNodeLabel, "Container", 2)

	resp, err := s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetOntologyProposals(), 1)
	p := resp.GetOntologyProposals()[0]
	require.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, p.GetKind())
	require.Equal(t, "Container", p.GetLabel())
	require.Equal(t, int32(2), p.GetSightingCount())
	require.Equal(t, "agent-1", p.GetLatestProposer())
	require.Equal(t, "sighted it", p.GetLatestClaim())
	require.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_PENDING, p.GetStatus())
	require.False(t, p.GetIsPromoted())
	require.Zero(t, p.GetTaxonomyVersion())
}

// TestListOntologyExtensionProposals_ReturnsTheRejection proves a rejected
// proposal carries its reviewer and its reason.
func TestListOntologyExtensionProposals_ReturnsTheRejection(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	ctx := ownerCtx("acme", "owner-1")
	proposeNTimes(ctx, t, reg.For("acme"), taxonomy.ProposedRelationshipType, "RUNS_ON", 1)
	_, err := s.RejectOntologyExtensionProposal(ctx, &tenantv1.RejectOntologyExtensionProposalRequest{
		Kind:   tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE,
		Label:  "RUNS_ON",
		Reason: "duplicate of DEPLOYED_ON",
	})
	require.NoError(t, err)
	waitForOntologyProposal(t, reg.For("acme"), "RUNS_ON", brain.OntologyProposalRejected)

	resp, err := s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetOntologyProposals(), 1)
	p := resp.GetOntologyProposals()[0]
	require.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE, p.GetKind())
	require.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_REJECTED, p.GetStatus())
	require.Equal(t, "owner-1", p.GetReviewer())
	require.Equal(t, "duplicate of DEPLOYED_ON", p.GetRejectionReason())
}

// TestListOntologyExtensionProposals_ReturnsThePromotion proves a promoted
// proposal says so and names the taxonomy version.
func TestListOntologyExtensionProposals_ReturnsThePromotion(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	ctx := ownerCtx("acme", "owner-1")
	promoteViaRPC(ctx, t, s, reg, "acme", taxonomy.ProposedNodeLabel, "Container")

	var p *tenantv1.OntologyExtensionProposal
	for range 200 {
		resp, err := s.ListOntologyExtensionProposals(tenantCtx("acme"), &tenantv1.ListOntologyExtensionProposalsRequest{})
		require.NoError(t, err)
		require.Len(t, resp.GetOntologyProposals(), 1)
		p = resp.GetOntologyProposals()[0]
		if p.GetIsPromoted() {
			break
		}
		reg.For("acme").Tick() //nolint:contextcheck // Tick is the synchronous drain of the engine
	}
	require.True(t, p.GetIsPromoted())
	require.Positive(t, p.GetTaxonomyVersion())
	require.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_APPROVED, p.GetStatus())
	require.Equal(t, "owner-1", p.GetReviewer())
}

// TestSubmitOntologyExtensionUpstream_ReturnsTheContribution proves the
// response carries the pack fragment and the text of the pull request that
// the tenant owner opens by hand (gibson#618).
func TestSubmitOntologyExtensionUpstream_ReturnsTheContribution(t *testing.T) {
	s, reg := newOntologyExtensionService(t)
	ctx := ownerCtx("acme", "owner-1")
	promoteViaRPC(ctx, t, s, reg, "acme", taxonomy.ProposedNodeLabel, "Container")

	resp, err := s.SubmitOntologyExtensionUpstream(subjectCtx(t, "acme", "owner-1"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetAuditRecordId())

	var pack struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal(resp.GetFragmentJson(), &pack))
	require.NotEmpty(t, pack.Name)
	require.Equal(t, "packs/"+pack.Name+".json", resp.GetPackFilePath())
	require.Equal(t, "Add domain pack contribution: "+pack.Name, resp.GetPullRequestTitle())
	require.Contains(t, resp.GetPullRequestBody(), "Container")
	require.Contains(t, resp.GetPullRequestBody(), resp.GetAuditRecordId())
}

// TestProposalWireConversions covers each value of the two enum conversions
// of the list response.
func TestProposalWireConversions(t *testing.T) {
	require.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_UNSPECIFIED, proposalKindToWire(taxonomy.ProposalKind(99)))
	require.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_UNSPECIFIED, proposalStatusToWire(brain.OntologyProposalStatus(99)))
	require.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_PENDING, proposalStatusToWire(brain.OntologyProposalPending))
	require.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_APPROVED, proposalStatusToWire(brain.OntologyProposalApproved))
	require.Equal(t, tenantv1.OntologyProposalStatus_ONTOLOGY_PROPOSAL_STATUS_REJECTED, proposalStatusToWire(brain.OntologyProposalRejected))
	require.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, proposalKindToWire(taxonomy.ProposedNodeLabel))
	require.Equal(t, tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE, proposalKindToWire(taxonomy.ProposedRelationshipType))
}
