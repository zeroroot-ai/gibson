// Package daemon — mission_projection.go
//
// missionDefinitionToProjected translates a CUE-authored gibson.mission.v1
// MissionDefinition into the brain-native brain.MissionProjected launch event
// (gibson#844). The brain stays proto-free (like the observation ingest path),
// so this proto→brain seam lives here. CUE declares dependencies, not a schedule:
// each node's deps are the union of its `dependencies` field and the incoming
// `edges`; the brain's Scheduler turns that into deterministic deferred ordering.
//
// This is the projection itself; wiring it onto live mission launch is the
// wholesale cutover (gibson#851). Control-flow nodes (condition/parallel/join)
// are handled by gibson#846, which extends this translator.
package daemon

import (
	"fmt"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/brain"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// missionDefinitionToProjected builds the launch event for a scripted mission.
// goal is the mission objective for the Decider (empty for a no-goal mission that
// runs its script deterministically and stops); it is supplied by the caller
// (dispatch request / mission metadata), not carried in the definition.
func missionDefinitionToProjected(def *missionpb.MissionDefinition, goal string) (brain.MissionProjected, error) {
	if def == nil {
		return brain.MissionProjected{}, fmt.Errorf("nil mission definition")
	}

	// Union deps: per-node `dependencies` + incoming `edges` (edge.from -> edge.to).
	deps := map[string]map[string]struct{}{}
	addDep := func(node, on string) {
		if deps[node] == nil {
			deps[node] = map[string]struct{}{}
		}
		deps[node][on] = struct{}{}
	}
	for id, n := range def.GetNodes() {
		for _, d := range n.GetDependencies() {
			addDep(id, d)
		}
	}
	for _, e := range def.GetEdges() {
		if e.GetFrom() != "" && e.GetTo() != "" {
			addDep(e.GetTo(), e.GetFrom())
		}
	}

	nodes := make([]brain.WorkNode, 0, len(def.GetNodes()))
	for id, n := range def.GetNodes() {
		kind, target, err := nodeKindTarget(n)
		if err != nil {
			return brain.MissionProjected{}, fmt.Errorf("node %q: %w", id, err)
		}
		nodes = append(nodes, brain.WorkNode{
			ID:        id,
			Kind:      kind,
			Target:    target,
			DependsOn: sortedKeys(deps[id]),
		})
	}
	// Deterministic node order (map iteration is random) for replay stability.
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return brain.MissionProjected{
		ID:     def.GetId(),
		Goal:   goal,
		Budget: budgetFromConstraints(def.GetConstraints()),
		Nodes:  nodes,
	}, nil
}

func nodeKindTarget(n *missionpb.MissionNode) (kind, target string, err error) {
	switch n.GetType() {
	case missionpb.NodeType_NODE_TYPE_AGENT:
		return "agent", n.GetAgentConfig().GetAgentName(), nil
	case missionpb.NodeType_NODE_TYPE_TOOL:
		return "tool", n.GetToolConfig().GetToolName(), nil
	case missionpb.NodeType_NODE_TYPE_PLUGIN:
		return "plugin", n.GetPluginConfig().GetPluginName(), nil
	default:
		// condition/parallel/join are gibson#846; unspecified is invalid.
		return "", "", fmt.Errorf("unsupported node type %s (control-flow nodes are gibson#846)", n.GetType())
	}
}

func budgetFromConstraints(c *missionpb.MissionConstraints) brain.Budget {
	if c == nil {
		return brain.Budget{}
	}
	// MaxExecutions (the runaway cap) has no proto field yet — gibson#849 sources
	// it. MaxTokens maps directly to the cumulative mission token budget.
	return brain.Budget{MaxTokens: c.GetMaxTokens()}
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
