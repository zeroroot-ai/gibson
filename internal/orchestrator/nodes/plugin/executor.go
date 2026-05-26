// Package plugin implements the PLUGIN node executor.
//
// PLUGIN = multi-method provider keyed by `plugin_name + method`.
// The executor delegates to the Actor's existing plugin gRPC
// dispatch.
//
// Spec: mission-verb-noun-registry Requirement 4 + Task 8.
package plugin

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/orchestrator"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// Execute is the NodeHandler for NODE_TYPE_PLUGIN.
func Execute(ctx context.Context, node *missionv1.MissionNode, params orchestrator.HandlerParams) (*orchestrator.ActionResult, error) {
	if params.Delegator == nil {
		return nil, fmt.Errorf("plugin executor: HandlerParams.Delegator is nil")
	}
	cfg := node.GetPluginConfig()
	if cfg == nil {
		return nil, fmt.Errorf("plugin executor: node %q has no plugin_config", node.GetId())
	}
	if cfg.GetPluginName() == "" {
		return nil, fmt.Errorf("plugin executor: node %q has empty plugin_name", node.GetId())
	}
	if cfg.GetMethod() == "" {
		return nil, fmt.Errorf("plugin executor: node %q has empty method", node.GetId())
	}
	return params.Delegator.ExecutePluginNode(ctx, node.GetId(), params.MissionID)
}

func init() {
	orchestrator.RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_PLUGIN, Execute)
}
