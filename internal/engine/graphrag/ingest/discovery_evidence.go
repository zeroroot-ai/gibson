// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// maxParserEvidenceBytes is the size limit of the content of one parser
// evidence item. It equals finding.MaxEvidenceContentBytes. The ingest package
// does not import the finding package, so the value is here. A test pins the
// two values together.
const maxParserEvidenceBytes = 1 << 20

// ParserSourceKey and ParserSource mark an evidence item that a parser read from
// tool output. The daemon sets them on each such item.
const (
	ParserSourceKey = "source"
	ParserSource    = "parser"
)

// recordRetries and recordRetryWait bound the wait for the record of the tool
// call. The harness hands the record to the World, and the World folds it on
// its next tick. The discovery goroutine can start before the fold.
const (
	recordRetries   = 10
	recordRetryWait = 100 * time.Millisecond
)

// parserEvidence returns the tier 2 evidence that parsers attached to the
// findings of a discovery result, keyed by the ID of the finding in the World.
// A FindingEvidence names its finding by the id that the parser gave the
// finding, or by the derived ID. Both match. The daemon sets the tier and the
// source. It clears the tool call id, because a parser cannot name a call. An
// item that is empty, too large or names no finding of the result is dropped,
// and the problem is returned.
func parserEvidence(execCtx ExecContext, d *graphragpb.DiscoveryResult) (map[string][]*typespb.Evidence, []error) {
	if len(d.GetFindingEvidence()) == 0 {
		return nil, nil
	}
	derived := make(map[string]string, 2*len(d.GetFindings()))
	for _, f := range d.GetFindings() {
		if f == nil || f.Title == "" {
			continue
		}
		id := findingID(execCtx.MissionID, f)
		derived[id] = id
		if orig := f.GetId(); orig != "" {
			derived[orig] = id
		}
	}
	var errs []error
	out := make(map[string][]*typespb.Evidence)
	for i, fe := range d.GetFindingEvidence() {
		item := fe.GetEvidence()
		if item == nil {
			errs = append(errs, fmt.Errorf("finding evidence %d has no evidence item", i))
			continue
		}
		id, ok := derived[fe.GetFindingId()]
		if !ok {
			errs = append(errs, fmt.Errorf("finding evidence %d names the unknown finding %q", i, fe.GetFindingId()))
			continue
		}
		if len(item.GetContent()) > maxParserEvidenceBytes {
			errs = append(errs, fmt.Errorf("finding evidence %d holds %d bytes, the limit is %d",
				i, len(item.GetContent()), maxParserEvidenceBytes))
			continue
		}
		clone, _ := proto.Clone(item).(*typespb.Evidence)
		clone.Tier = typespb.EvidenceTier_EVIDENCE_TIER_TYPED
		clone.ToolCallId = ""
		if clone.Metadata == nil {
			clone.Metadata = map[string]string{}
		}
		clone.Metadata[ParserSourceKey] = ParserSource
		out[id] = append(out[id], clone)
	}
	return out, errs
}

// noToolCallRecord is the record source of a processor with no wiring. It holds
// no call, and it names no call as missing, so the processor adds no tier 1
// item.
type noToolCallRecord struct{}

func (noToolCallRecord) RecordedToolCalls(context.Context, string, []string) ([]brain.AgentToolCallSnapshot, []string, error) {
	return nil, nil, nil
}

// recordedToolEvidence returns the tier 1 item of the tool call whose output
// was parsed. It returns nil when the discovery has no tool call, when the
// source holds no record of the call, or when the call has no record after the
// wait.
func (p *discoveryProcessor) recordedToolEvidence(ctx context.Context, execCtx ExecContext) (*typespb.Evidence, error) {
	if execCtx.ToolExecutionID == "" || execCtx.MissionID == "" {
		return nil, nil
	}
	// The record is read for the tenant of the discovery. The context of the
	// goroutine that runs the processor holds no tenant.
	ctx = auth.WithTenant(ctx, execCtx.TenantID)
	for attempt := 0; ; attempt++ {
		items, missing, err := brain.ReadRecordedEvidence(ctx, p.records, execCtx.MissionID, []string{execCtx.ToolExecutionID})
		if err != nil {
			return nil, fmt.Errorf("read the record of tool call %s: %w", execCtx.ToolExecutionID, err)
		}
		if len(items) > 0 {
			return items[0], nil
		}
		if len(missing) == 0 {
			return nil, nil // the source holds no record and names none missing
		}
		if attempt >= recordRetries {
			return nil, fmt.Errorf("tool call %s has no record", execCtx.ToolExecutionID)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for the record of tool call %s: %w", execCtx.ToolExecutionID, ctx.Err())
		case <-time.After(recordRetryWait):
		}
	}
}
