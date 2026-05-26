package all_test

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/orchestrator"
	_ "github.com/zeroroot-ai/gibson/internal/orchestrator/nodes/all"
)

// TestAggregator_registers_concrete_nouns asserts that importing
// nodes/all sufficiently registers the per-noun packages
// currently wired through it (CONDITION, PARALLEL, JOIN).
//
// AGENT, TOOL, PLUGIN are deferred until Tasks 6-8 of
// mission-verb-noun-registry; we don't assert them here.
func TestAggregator_registers_concrete_nouns(t *testing.T) {
	wired := []string{
		"NODE_TYPE_CONDITION",
		"NODE_TYPE_PARALLEL",
		"NODE_TYPE_JOIN",
	}
	for _, name := range wired {
		t.Run(name, func(t *testing.T) {
			// Use the registry's resolution helper via the
			// orchestrator package surface.
			// We can't import missionv1 here without circular
			// imports through our test deps, so resolve via
			// the exhaustiveness assertion API.
			err := orchestrator.AssertNodeRegistryExhaustiveWithSkip(map[string]struct{}{
				"NODE_TYPE_AGENT":  {},
				"NODE_TYPE_TOOL":   {},
				"NODE_TYPE_PLUGIN": {},
			})
			if err != nil {
				t.Errorf("registry incomplete with AGENT/TOOL/PLUGIN deferred: %v", err)
			}
		})
	}
}
