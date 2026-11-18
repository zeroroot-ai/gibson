// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
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

	got, err := decodeFindingPayload([]byte(raw))

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
	_, err := decodeFindingPayload([]byte(`{"title":`))
	require.Error(t, err)
}
