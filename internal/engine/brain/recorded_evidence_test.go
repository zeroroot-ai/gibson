// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

func TestRecordedEvidence(t *testing.T) {
	got := RecordedEvidence([]AgentToolCallSnapshot{
		{ToolCallID: "c1", ToolName: "httpx", Result: "first", RecordedAtUnixNano: 7},
		{ToolCallID: "c2", ToolName: "nmap", Result: "second"},
	})

	require.Len(t, got, 2)
	assert.Equal(t, "first", got[0].GetContent())
	assert.Equal(t, "c1", got[0].GetToolCallId())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, got[0].GetTier())
	assert.Equal(t, "httpx", got[0].GetMetadata()["tool_name"])
	assert.Equal(t, "7", got[0].GetMetadata()["recorded_at_unix_nano"])
	assert.Equal(t, "tool call nmap (c2)", got[1].GetTitle())
	assert.Empty(t, RecordedEvidence(nil))
}
