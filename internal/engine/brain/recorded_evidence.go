// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"fmt"
	"strconv"

	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// RecordedEvidence turns the records of tool calls into tier 1 evidence. The
// content of an item is the result that the tool returned, as the flight
// recorder stored it after the redaction for the tenant (ADR-0120). Nothing in
// an item comes from an agent. An agent only chooses which tool calls to name.
func RecordedEvidence(calls []AgentToolCallSnapshot) []*typespb.Evidence {
	out := make([]*typespb.Evidence, len(calls))
	for i, c := range calls {
		out[i] = &typespb.Evidence{
			Title:      fmt.Sprintf("tool call %s (%s)", c.ToolName, c.ToolCallID),
			Type:       typespb.EvidenceType_EVIDENCE_TYPE_LOG,
			Content:    c.Result,
			Tier:       typespb.EvidenceTier_EVIDENCE_TIER_RECORDED,
			ToolCallId: c.ToolCallID,
			Metadata: map[string]string{
				"tool_name":             c.ToolName,
				"recorded_at_unix_nano": strconv.FormatInt(c.RecordedAtUnixNano, 10),
			},
		}
	}
	return out
}
