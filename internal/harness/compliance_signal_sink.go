package harness

import (
	"context"
	"fmt"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	taxonomypb "github.com/zero-day-ai/sdk/api/gen/taxonomy/v1"
)

// DiscoveryProcessorSink is the production SignalSink that packs a
// compliance signal into a DiscoveryResult and routes it through the
// existing DiscoveryProcessor pipeline. This is the only SignalSink
// implementation in production — tests use fakes.
//
// The sink reuses the entire extraction → processor → loader → Neo4j
// pipeline that tool discoveries already use, per
// audit-compliance-emitter Requirement 6.1.
type DiscoveryProcessorSink struct {
	// processor is the narrow interface we need from the discovery
	// processor. Defined locally to avoid importing the processor
	// package (which would create a cycle via graphrag → harness).
	processor DiscoveryResultProcessor
	metrics   *ComplianceMetrics
}

// DiscoveryResultProcessor is the narrow interface the sink needs from
// the DiscoveryProcessor. The real implementation is
// core/gibson/internal/graphrag/processor.DiscoveryProcessor.
type DiscoveryResultProcessor interface {
	// ProcessDiscoveryResult processes a DiscoveryResult, persisting its
	// entities and relationships to the graph.
	ProcessDiscoveryResult(ctx context.Context, dr *graphragpb.DiscoveryResult) error
}

// NewDiscoveryProcessorSink constructs a production SignalSink.
func NewDiscoveryProcessorSink(processor DiscoveryResultProcessor, metrics *ComplianceMetrics) *DiscoveryProcessorSink {
	return &DiscoveryProcessorSink{
		processor: processor,
		metrics:   metrics,
	}
}

// Emit packs the signal into a DiscoveryResult and hands it to the
// processor. The processor handles tenant scoping, Neo4j writes, and
// parent-relationship wiring (EMITTED_SIGNAL → agent_run).
func (s *DiscoveryProcessorSink) Emit(ctx context.Context, sig *taxonomypb.ComplianceSignal) error {
	if s.processor == nil {
		return fmt.Errorf("compliance signal sink: processor is nil")
	}

	dr := &graphragpb.DiscoveryResult{
		ComplianceSignals: []*taxonomypb.ComplianceSignal{sig},
	}

	if err := s.processor.ProcessDiscoveryResult(ctx, dr); err != nil {
		return fmt.Errorf("compliance signal persistence: %w", err)
	}
	return nil
}
