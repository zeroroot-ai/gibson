package orchestrator

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/types"
)

// Actor implements the NodeDelegator interface declared in
// registry.go. The per-noun packages under
// `internal/orchestrator/nodes/{agent,tool,plugin}` call back
// through this interface to reach the Actor's existing
// per-action methods (executeAgent / per-tool dispatch /
// per-plugin dispatch).
//
// This indirection keeps the registry pattern data-driven
// without forcing executor packages to be rewritten with the
// Actor's full collaborator graph (graph queries, harness,
// checkpoint manager, policy checker, etc.).
//
// Spec: mission-verb-noun-registry Requirement 2 + Tasks 6, 7, 8.

// ExecuteAgentNode implements NodeDelegator.ExecuteAgentNode.
//
// Constructs an internal Decision from the (nodeID, missionID)
// pair and invokes the existing executeAgent method, preserving
// every Actor-internal behavior (policy gate, implicit
// checkpoint, status updates, harness delegation, finding
// extraction).
func (a *Actor) ExecuteAgentNode(ctx context.Context, nodeID, missionID string) (*ActionResult, error) {
	parsedMissionID, err := types.ParseID(missionID)
	if err != nil {
		return nil, err
	}
	d := &Decision{
		Action:       ActionExecuteAgent,
		TargetNodeID: nodeID,
	}
	return a.executeAgent(ctx, d, parsedMissionID)
}

// ExecuteToolNode implements NodeDelegator.ExecuteToolNode.
//
// Currently routes through the existing executeAgent path; the
// existing dispatch checks node.Type and surfaces a clear error
// when the type isn't AGENT (act.go:240). Once a TOOL-specific
// dispatch path lands in the Actor (separate refactor), this
// method redirects there. The per-noun executor in
// nodes/tool/ already validates ToolNodeConfig presence before
// reaching this delegate, so we surface the act-level error
// untouched.
func (a *Actor) ExecuteToolNode(ctx context.Context, nodeID, missionID string) (*ActionResult, error) {
	parsedMissionID, err := types.ParseID(missionID)
	if err != nil {
		return nil, err
	}
	d := &Decision{
		Action:       ActionExecuteAgent,
		TargetNodeID: nodeID,
	}
	return a.executeAgent(ctx, d, parsedMissionID)
}

// ExecutePluginNode implements NodeDelegator.ExecutePluginNode.
//
// Same routing pattern as ExecuteToolNode — see comment there.
func (a *Actor) ExecutePluginNode(ctx context.Context, nodeID, missionID string) (*ActionResult, error) {
	parsedMissionID, err := types.ParseID(missionID)
	if err != nil {
		return nil, err
	}
	d := &Decision{
		Action:       ActionExecuteAgent,
		TargetNodeID: nodeID,
	}
	return a.executeAgent(ctx, d, parsedMissionID)
}

// Compile-time assertion that *Actor satisfies NodeDelegator.
var _ NodeDelegator = (*Actor)(nil)
