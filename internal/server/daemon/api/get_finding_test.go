// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

func TestGetFinding_NilPool_Unavailable(t *testing.T) {
	t.Parallel()
	_, err := (&DaemonServer{}).GetFinding(context.Background(), &tenantv1.GetFindingRequest{FindingId: "x"})
	assert.Equal(t, codes.Unavailable, status_grpc.Code(err))
}

func TestFindingToDetail_HoldsEveryEvidenceItemWithItsTier(t *testing.T) {
	t.Parallel()
	f := finding.EnhancedFinding{
		Finding: agent.Finding{
			ID: "5b4b8e9e-8e8e-4c8e-9e8e-8e8e8e8e8e8e", Title: "open redirect", Severity: agent.SeverityHigh,
			Evidence: []*typespb.Evidence{
				{Content: "recorded", Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, ToolCallId: "call-1"},
				{Content: "typed", Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED},
			},
		},
		AgentName: "recon",
	}

	d := findingToDetail(f)

	assert.Equal(t, f.ID.String(), d.GetId())
	assert.Equal(t, "recon", d.GetAgentName())
	require.Len(t, d.GetEvidence(), 2)
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, d.GetEvidence()[0].GetTier())
	assert.Equal(t, "call-1", d.GetEvidence()[0].GetToolCallId())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, d.GetEvidence()[1].GetTier())
}
