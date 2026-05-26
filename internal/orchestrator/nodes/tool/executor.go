// Package tool implements the TOOL node executor.
//
// TOOL = single-purpose named function with a typed input map.
// The executor delegates to the Actor's existing tool dispatch
// pipeline, which goes through the harness's tool worker queue
// (Redis BRPOP per tech.md decision-log entry 7).
//
// Spec: mission-verb-noun-registry Requirement 3 + Task 7.
package tool

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// Execute is the NodeHandler for NODE_TYPE_TOOL.
func Execute(ctx context.Context, node *missionv1.MissionNode, params orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
	if params.Delegator == nil {
		return nil, fmt.Errorf("tool executor: HandlerParams.Delegator is nil")
	}
	cfg := node.GetToolConfig()
	if cfg == nil {
		return nil, fmt.Errorf("tool executor: node %q has no tool_config", node.GetId())
	}
	if cfg.GetToolName() == "" {
		return nil, fmt.Errorf("tool executor: node %q has empty tool_name", node.GetId())
	}
	return params.Delegator.ExecuteToolNode(ctx, node.GetId(), params.MissionID)
}

func init() {
	orchestrator.RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_TOOL, Execute)
}
