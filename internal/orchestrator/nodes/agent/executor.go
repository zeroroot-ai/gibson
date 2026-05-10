// Package agent implements the AGENT node executor.
//
// AGENT = LLM-driven worker that calls tools and plugins. The
// executor delegates to the Actor's existing per-agent execution
// pipeline (policy check → checkpoint → graph state →
// harness.DelegateToAgent → finding extraction). The delegation
// indirection keeps the registry dispatch data-driven without
// duplicating the Actor's collaborator graph.
//
// Spec: mission-verb-noun-registry Requirement 2 + Task 6.
package agent

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// Execute is the NodeHandler for NODE_TYPE_AGENT.
func Execute(ctx context.Context, node *missionv1.MissionNode, params orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
	if params.Delegator == nil {
		return nil, fmt.Errorf("agent executor: HandlerParams.Delegator is nil; orchestrator must inject the Actor delegate")
	}
	if node.GetAgentConfig() == nil {
		return nil, fmt.Errorf("agent executor: node %q has no agent_config", node.GetId())
	}
	return params.Delegator.ExecuteAgentNode(ctx, node.GetId(), params.MissionID)
}

func init() {
	orchestrator.RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_AGENT, Execute)
}
