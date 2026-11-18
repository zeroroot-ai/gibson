// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
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

// ErrTooManyToolCalls reports a request that names more tool calls than
// MaxProofToolCallIDs.
var ErrTooManyToolCalls = errors.New("brain: too many tool calls named")

// ToolCallRecord reads the tool calls that the daemon recorded. The tenant is on
// the context. A record of another mission counts as missing.
type ToolCallRecord interface {
	RecordedToolCalls(ctx context.Context, missionID string, ids []string) (found []AgentToolCallSnapshot, missing []string, err error)
}

// ReadRecordedEvidence is the one function that reads the record of tool calls
// for a proof, for a finding on the harness callback path and for a finding on
// the component path. It drops a repeated ID, checks the limit, reads the
// record of the mission in the tenant of the context, and builds the tier 1
// items with RecordedEvidence. It returns the IDs that name no record, and it
// returns no evidence if one ID is missing. An empty list gives no evidence.
func ReadRecordedEvidence(
	ctx context.Context, src ToolCallRecord, missionID string, toolCallIDs []string,
) (evidence []*typespb.Evidence, missing []string, err error) {
	seen := make(map[string]struct{}, len(toolCallIDs))
	ids := make([]string, 0, len(toolCallIDs))
	for _, id := range toolCallIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, nil, nil
	}
	if len(ids) > MaxProofToolCallIDs {
		return nil, nil, fmt.Errorf("%w: %d calls, the limit is %d", ErrTooManyToolCalls, len(ids), MaxProofToolCallIDs)
	}
	calls, missing, err := src.RecordedToolCalls(ctx, missionID, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("read recorded tool calls: %w", err)
	}
	if len(missing) > 0 {
		return nil, missing, nil
	}
	return RecordedEvidence(calls), nil, nil
}
