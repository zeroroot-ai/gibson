// Package all blank-imports every per-noun executor package so
// the NodeHandler registry is fully populated by the time the
// orchestrator's main loop dispatches its first node.
//
// Importing this package from the orchestrator's construction
// site (factory / main) ensures every NodeType has a handler
// before AssertNodeRegistryExhaustive runs.
//
// Spec: mission-verb-noun-registry Requirement 2 ACs 1, 4 +
//       Task 9.
package all

import (
	// Per-noun packages register at their init(). Order is
	// irrelevant — registration is via package init, not import
	// order.
	_ "github.com/zero-day-ai/gibson/internal/orchestrator/nodes/agent"
	_ "github.com/zero-day-ai/gibson/internal/orchestrator/nodes/condition"
	_ "github.com/zero-day-ai/gibson/internal/orchestrator/nodes/join"
	_ "github.com/zero-day-ai/gibson/internal/orchestrator/nodes/parallel"
	_ "github.com/zero-day-ai/gibson/internal/orchestrator/nodes/plugin"
	_ "github.com/zero-day-ai/gibson/internal/orchestrator/nodes/tool"

	"github.com/zero-day-ai/gibson/internal/orchestrator"
)

// AssertExhaustive runs the registry's exhaustiveness check
// against the SDK's full NodeType enum. Surfaced as a top-level
// function so callers (e.g. the daemon's bootstrap) can invoke
// it after constructing the orchestrator.
//
// All six concrete NodeTypes (AGENT, TOOL, PLUGIN, CONDITION,
// PARALLEL, JOIN) register via this aggregator's blank imports.
// AGENT / TOOL / PLUGIN executors delegate back to the Actor
// via HandlerParams.Delegator; CONDITION / PARALLEL / JOIN
// executors run pure / scoped-state-only logic.
//
// `skip` is retained for tests that want to assert on a subset
// (e.g. CONDITION-only registries).
func AssertExhaustive(skip ...string) error {
	skipSet := make(map[string]struct{}, len(skip))
	for _, s := range skip {
		skipSet[s] = struct{}{}
	}
	return orchestrator.AssertNodeRegistryExhaustiveWithSkip(skipSet)
}
