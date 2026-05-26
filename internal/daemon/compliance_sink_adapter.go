package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/graphrag/loader"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	taxonomypb "github.com/zeroroot-ai/sdk/api/gen/taxonomy/v1"
)

// complianceSignalSink adapts the DiscoveryProcessor to the
// harness.SignalSink interface so the ComplianceMiddleware can persist
// compliance signals through the same pipeline as tool discoveries.
//
// The sink packs the signal into a DiscoveryResult and hands it to the
// processor, which delegates to the GraphLoader. The loader writes the
// signal as a compliance_signal node in Neo4j with an EMITTED_SIGNAL
// parent relationship to the originating agent_run (using the auto-wired
// ParentRelationships map from the taxonomy).
type complianceSignalSink struct {
	proc   ingest.DiscoveryProcessor
	logger *slog.Logger
}

// newComplianceSignalSink constructs the sink. Returns nil if the
// processor is nil (graphrag disabled) — the harness factory treats a
// nil ComplianceSink as "emitter not wired".
func newComplianceSignalSink(proc ingest.DiscoveryProcessor, logger *slog.Logger) *complianceSignalSink {
	if proc == nil {
		return nil
	}
	return &complianceSignalSink{proc: proc, logger: logger}
}

// Emit satisfies harness.SignalSink.
func (s *complianceSignalSink) Emit(ctx context.Context, sig *taxonomypb.ComplianceSignal) error {
	if s.proc == nil {
		return fmt.Errorf("compliance signal sink: processor is nil")
	}

	dr := &graphragpb.DiscoveryResult{
		ComplianceSignals: []*taxonomypb.ComplianceSignal{sig},
	}

	// Build execution context from the signal itself — the signal
	// already carries mission_id, mission_run_id, agent_run_id.
	var missionID, missionRunID, agentRunID string
	if sig.MissionId != nil {
		missionID = *sig.MissionId
	}
	if sig.MissionRunId != nil {
		missionRunID = *sig.MissionRunId
	}
	if sig.AgentRunId != nil {
		agentRunID = *sig.AgentRunId
	}

	execCtx := loader.ExecContext{
		MissionID:    missionID,
		MissionRunID: missionRunID,
		AgentName:    sig.CallerComponent,
		AgentRunID:   agentRunID,
	}

	result, err := s.proc.Process(ctx, execCtx, dr)
	if err != nil {
		return fmt.Errorf("compliance signal persistence: %w", err)
	}

	if result != nil && result.NodesCreated > 0 {
		s.logger.DebugContext(ctx, "compliance signal persisted",
			slog.String("signal_id", sig.SignalId),
			slog.String("action", sig.Action),
			slog.Int("nodes_created", result.NodesCreated),
		)
	}
	return nil
}
