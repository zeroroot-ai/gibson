// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// TestDecodeFindingPayload_EvidenceIsTier2 proves that the JSON of an SDK
// finding decodes. The evidence has the SDK shape, and the agent typed it, so
// each item is tier 2.
func TestDecodeFindingPayload_EvidenceIsTier2(t *testing.T) {
	raw := `{
		"title": "open redirect",
		"severity": "medium",
		"evidence": [
			{"type": "conversation", "title": "dialogue", "content": "hello", "metadata": {"turns": 2}},
			{"type": "http_request", "title": "request", "content": "GET /"},
			{"type": "something_new", "title": "other", "content": "x"}
		],
		"tool_call_ids": ["call-1"]
	}`

	got, _, err := decodeFindingPayload([]byte(raw))

	require.NoError(t, err)
	assert.Equal(t, "open redirect", got.Title)
	assert.Equal(t, agent.SeverityMedium, got.Severity)
	require.Len(t, got.Evidence, 3)
	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION, got.Evidence[0].GetType())
	assert.Equal(t, "hello", got.Evidence[0].GetContent())
	assert.Equal(t, "2", got.Evidence[0].GetMetadata()["turns"])
	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_REQUEST, got.Evidence[1].GetType())
	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_OTHER, got.Evidence[2].GetType())
	for _, e := range got.Evidence {
		assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, e.GetTier())
		assert.Empty(t, e.GetToolCallId())
	}
}

func TestDecodeFindingPayload_RejectsBadJSON(t *testing.T) {
	_, _, err := decodeFindingPayload([]byte(`{"title":`))
	require.Error(t, err)
}

// stubToolCallRecord holds recorded tool calls by mission.
type stubToolCallRecord struct {
	calls map[string][]brain.AgentToolCallSnapshot // by mission
}

func (s *stubToolCallRecord) RecordedToolCalls(
	_ context.Context, missionID string, ids []string,
) (found []brain.AgentToolCallSnapshot, missing []string, err error) {
	for _, id := range ids {
		var hit *brain.AgentToolCallSnapshot
		for i := range s.calls[missionID] {
			if s.calls[missionID][i].ToolCallID == id {
				hit = &s.calls[missionID][i]
			}
		}
		if hit == nil {
			missing = append(missing, id)
			continue
		}
		found = append(found, *hit)
	}
	return found, missing, nil
}

func TestDecodeFindingPayload_ReturnsTheToolCallIDs(t *testing.T) {
	_, ids, err := decodeFindingPayload([]byte(`{"title":"x","tool_call_ids":["a","b"]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, ids)
}

func TestFindingSubmitter_RecordedEvidence(t *testing.T) {
	mission := types.NewID()
	record := &stubToolCallRecord{calls: map[string][]brain.AgentToolCallSnapshot{
		mission.String():     {{ToolCallID: "call-1", ToolName: "httpx", Result: "recorded"}},
		"another-mission-id": {{ToolCallID: "call-other", Result: "other"}},
	}}
	s := NewGraphRAGFindingSubmitter(nil, nil, nil, testLogger()).WithToolCallRecord(record)
	ctx := context.Background()

	got, err := s.recordedEvidence(ctx, mission, []string{"call-1"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, got[0].GetTier())
	assert.Equal(t, "recorded", got[0].GetContent())
	assert.Equal(t, "call-1", got[0].GetToolCallId())

	for name, ids := range map[string][]string{
		"unknown id":              {"nope"},
		"one known, one unknown":  {"call-1", "nope"},
		"call of another mission": {"call-other"},
	} {
		_, err := s.recordedEvidence(ctx, mission, ids)
		require.ErrorIs(t, err, ErrToolCallNotRecorded, name)
	}

	_, err = s.recordedEvidence(ctx, "", []string{"call-1"})
	require.ErrorIs(t, err, ErrToolCallNotRecorded, "a finding with no mission cannot name a tool call")

	none, err := s.recordedEvidence(ctx, mission, nil)
	require.NoError(t, err)
	assert.Empty(t, none)

	_, err = NewGraphRAGFindingSubmitter(nil, nil, nil, testLogger()).recordedEvidence(ctx, mission, []string{"call-1"})
	require.ErrorIs(t, err, ErrToolCallRecordUnavailable)
}

// TestFindingSubmitter_NamedToolCallWithNoRecordFailsTheSubmit proves that the
// whole submit fails and the World sink sees nothing.
func TestFindingSubmitter_NamedToolCallWithNoRecordFailsTheSubmit(t *testing.T) {
	var seen finding.EnhancedFinding
	s := NewGraphRAGFindingSubmitter(recordingSink(&seen), nil, nil, testLogger()).
		WithToolCallRecord(&stubToolCallRecord{})

	_, err := s.Submit(submitterCtx(victimTenant, "agent_principal:sa-1"), victimTenant, "",
		`{"title":"x","tool_call_ids":["call-1"]}`, "", "")

	require.ErrorIs(t, err, ErrToolCallNotRecorded)
	assert.Empty(t, seen.ID)
}
