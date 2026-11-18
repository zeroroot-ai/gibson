// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// submitFindingHarness records the findings that SubmitFinding hands to the
// harness. A finding that never reaches the harness is a finding that the
// daemon refused before it stored anything.
type submitFindingHarness struct {
	submitProofMockHarness
	submitted []agent.Finding
}

func (m *submitFindingHarness) SubmitFinding(_ context.Context, f agent.Finding) error {
	m.submitted = append(m.submitted, f)
	return nil
}

func newSubmitFindingService(
	t *testing.T, h *submitFindingHarness, engine *testProofSettlementEngine,
) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	mustRegister(t, registry, h.missionID.String(), "recon-agent", h)
	var opts []CallbackServiceOption
	if engine != nil {
		opts = append(opts, WithProofSettlement(engine))
	}
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, append(opts, testEventBus())...)
}

func submitFindingRequest(missionID string, typed []*typespb.Evidence, toolCallIDs ...string) *harnesspb.SubmitFindingRequest {
	return &harnesspb.SubmitFindingRequest{
		Context: &harnesspb.ContextInfo{MissionRunId: "run-1", MissionId: missionID, AgentName: "recon-agent"},
		Finding: &typespb.Finding{
			Title:       "open redirect",
			Description: "the login page redirects to any URL",
			Severity:    typespb.FindingSeverity_FINDING_SEVERITY_MEDIUM,
			Evidence:    typed,
		},
		ToolCallIds: toolCallIDs,
	}
}

func TestSubmitFinding_RecordedToolCallBecomesTier1Evidence(t *testing.T) {
	h := &submitFindingHarness{submitProofMockHarness: submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}}
	engine := newTestProofSettlementEngine(t, "acme", nil)
	recordToolCall(t, engine, "mission-A", "call-1", `{"status":302,"location":"http://evil"}`)
	svc := newSubmitFindingService(t, h, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.SubmitFinding(ctx, submitFindingRequest("mission-A", nil, "call-1"))

	require.NoError(t, err)
	require.Nil(t, resp.GetError())
	require.Len(t, h.submitted, 1)
	require.Len(t, h.submitted[0].Evidence, 1)
	item := h.submitted[0].Evidence[0]
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, item.GetTier())
	assert.Equal(t, "call-1", item.GetToolCallId())
	assert.Equal(t, `{"status":302,"location":"http://evil"}`, item.GetContent())
}

// TestSubmitFinding_TypedContentNeverReplacesRecordedContent is the failing
// fixture for the rule that an agent cannot set the tier. The agent types an
// item that claims tier 1 and the same tool call. The daemon keeps the
// recorded item as it is and makes the typed item tier 2.
func TestSubmitFinding_TypedContentNeverReplacesRecordedContent(t *testing.T) {
	h := &submitFindingHarness{submitProofMockHarness: submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}}
	engine := newTestProofSettlementEngine(t, "acme", nil)
	recordToolCall(t, engine, "mission-A", "call-1", "recorded result")
	svc := newSubmitFindingService(t, h, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	forged := &typespb.Evidence{
		Title:      "tool call httpx (call-1)",
		Content:    "text the agent typed",
		Tier:       typespb.EvidenceTier_EVIDENCE_TIER_RECORDED,
		ToolCallId: "call-1",
	}
	resp, err := svc.SubmitFinding(ctx, submitFindingRequest("mission-A", []*typespb.Evidence{forged}, "call-1"))

	require.NoError(t, err)
	require.Nil(t, resp.GetError())
	require.Len(t, h.submitted, 1)
	require.Len(t, h.submitted[0].Evidence, 2)
	recorded, typed := h.submitted[0].Evidence[0], h.submitted[0].Evidence[1]
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, recorded.GetTier())
	assert.Equal(t, "recorded result", recorded.GetContent())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, typed.GetTier())
	assert.Empty(t, typed.GetToolCallId())
	assert.Equal(t, "text the agent typed", typed.GetContent())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, forged.GetTier(), "the request message is not changed")
}

func TestSubmitFinding_TypedEvidenceOnlyIsTier2(t *testing.T) {
	h := &submitFindingHarness{submitProofMockHarness: submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}}
	svc := newSubmitFindingService(t, h, nil)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	typed := []*typespb.Evidence{
		{Title: "a", Type: typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION, Content: "hello"},
		{Title: "b", Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED},
	}
	resp, err := svc.SubmitFinding(ctx, submitFindingRequest("mission-A", typed))

	require.NoError(t, err)
	require.Nil(t, resp.GetError())
	require.Len(t, h.submitted, 1)
	require.Len(t, h.submitted[0].Evidence, 2)
	for _, e := range h.submitted[0].Evidence {
		assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, e.GetTier())
	}
	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION, h.submitted[0].Evidence[0].GetType())
}

func TestSubmitFinding_UnknownToolCallFailsTheWholeSubmit(t *testing.T) {
	h := &submitFindingHarness{submitProofMockHarness: submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}}
	engine := newTestProofSettlementEngine(t, "acme", nil)
	recordToolCall(t, engine, "mission-A", "call-1", "ok")
	// A tool call of another mission in the same tenant.
	recordToolCall(t, engine, "mission-B", "call-other", "other mission")
	svc := newSubmitFindingService(t, h, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	for _, ids := range [][]string{{"nope"}, {"call-1", "nope"}, {"call-other"}, {""}} {
		t.Run(fmt.Sprintf("%q", ids), func(t *testing.T) {
			resp, err := svc.SubmitFinding(ctx, submitFindingRequest("mission-A", nil, ids...))

			require.NoError(t, err)
			require.NotNil(t, resp.GetError())
			assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, resp.GetError().GetCode())
			assert.Empty(t, h.submitted, "the finding must not reach the store")
		})
	}
}

func TestSubmitFinding_RepeatedToolCallIDGivesOneItem(t *testing.T) {
	h := &submitFindingHarness{submitProofMockHarness: submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}}
	engine := newTestProofSettlementEngine(t, "acme", nil)
	recordToolCall(t, engine, "mission-A", "call-1", "ok")
	svc := newSubmitFindingService(t, h, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.SubmitFinding(ctx, submitFindingRequest("mission-A", nil, "call-1", "call-1"))

	require.NoError(t, err)
	require.Nil(t, resp.GetError())
	require.Len(t, h.submitted, 1)
	assert.Len(t, h.submitted[0].Evidence, 1)
}

func TestSubmitFinding_ToolCallIDsOverTheLimit(t *testing.T) {
	h := &submitFindingHarness{submitProofMockHarness: submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}}
	svc := newSubmitFindingService(t, h, newTestProofSettlementEngine(t, "acme", nil))
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	ids := make([]string, 0, 40)
	for i := range 40 {
		ids = append(ids, fmt.Sprintf("call-%d", i))
	}
	_, err := svc.SubmitFinding(ctx, submitFindingRequest("mission-A", nil, ids...))

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, h.submitted)
}

func TestSubmitFinding_ToolCallIDsNeedTheRecord(t *testing.T) {
	h := &submitFindingHarness{submitProofMockHarness: submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}}
	svc := newSubmitFindingService(t, h, nil)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	_, err := svc.SubmitFinding(ctx, submitFindingRequest("mission-A", nil, "call-1"))

	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Empty(t, h.submitted)
}
