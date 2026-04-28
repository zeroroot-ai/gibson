package daemon

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/graphrag/ingest"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
)

// discoveryProcessorAdapter adapts ingest.DiscoveryProcessor to orchestrator.DiscoveryProcessor.
// This is needed because the orchestrator defines its own interface to avoid import cycles.
type discoveryProcessorAdapter struct {
	processor ingest.DiscoveryProcessor
}

// ProcessAgentDiscovery implements orchestrator.DiscoveryProcessor.
// It stores discovered nodes from a proto DiscoveryResult in the graph.
func (a *discoveryProcessorAdapter) ProcessAgentDiscovery(ctx context.Context, missionID, missionRunID, agentName, agentRunID string, discovery *graphragpb.DiscoveryResult) (nodesCreated int, err error) {
	if a.processor == nil {
		return 0, nil
	}

	// Build execution context with MissionRunID for proper scoping
	execCtx := loader.ExecContext{
		MissionRunID: missionRunID,
		MissionID:    missionID,
		AgentName:    agentName,
		AgentRunID:   agentRunID,
	}

	// Process discovery
	result, err := a.processor.Process(ctx, execCtx, discovery)
	if err != nil {
		return 0, err
	}

	if result != nil {
		return result.NodesCreated, nil
	}

	return 0, nil
}
