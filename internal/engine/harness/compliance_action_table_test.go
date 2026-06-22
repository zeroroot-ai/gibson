package harness

import (
	"reflect"
	"strings"
	"testing"
)

// TestActionTableCoversAgentHarnessInterface is the reflection-based coverage
// assertion required by task 2 of audit-compliance-emitter. Every method
// declared on the AgentHarness interface must be present in the default
// action table, either as an emitting entry or as a non-emitting getter.
//
// When a new method is added to AgentHarness without a corresponding entry
// in compliance_action_table.go, this test fails and the author is forced to
// classify the new method explicitly.
//
// Memory tier operations are exempt — they are not methods on AgentHarness
// itself; they are accessed via Memory() and wrapped separately.
func TestActionTableCoversAgentHarnessInterface(t *testing.T) {
	iface := reflect.TypeOf((*AgentHarness)(nil)).Elem()
	table := DefaultActionTable()

	// Methods that return interfaces which are wrapped elsewhere and whose
	// top-level access is a pure getter. These must still have an entry
	// (non-emitting), because the getter itself crosses the harness boundary.
	// The test asserts they are present but allows Emit=false.
	_ = map[string]bool{
		"Memory":     true,
		"Checkpoint": true,
		"Tracer":     true,
		"Logger":     true,
		"Metrics":    true,
		"TokenUsage": true,
	}

	missing := []string{}
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		key := HarnessMethod(name)
		if _, ok := table.Lookup(key); !ok {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Fatalf("action table missing entries for AgentHarness methods: %s\n"+
			"add each missing method to compliance_action_table.go with an appropriate "+
			"ActionEntry (use Emit=false for pure getters)",
			strings.Join(missing, ", "))
	}
}

// TestActionTableHasNoStaleEntries is the inverse check: every non-memory
// entry in the table must correspond to a real method on AgentHarness (memory
// tier ops are exempt because they are not methods on AgentHarness itself).
// This catches the case where a method is renamed or removed without
// updating the table.
func TestActionTableHasNoStaleEntries(t *testing.T) {
	iface := reflect.TypeOf((*AgentHarness)(nil)).Elem()
	realMethods := map[string]bool{}
	for i := 0; i < iface.NumMethod(); i++ {
		realMethods[iface.Method(i).Name] = true
	}

	// Memory tier ops are virtual keys — they are not methods on
	// AgentHarness but on the memory store returned by Memory().
	exempt := map[HarnessMethod]bool{}

	stale := []HarnessMethod{}
	for m := range DefaultActionTable() {
		if exempt[m] {
			continue
		}
		if !realMethods[string(m)] {
			stale = append(stale, m)
		}
	}

	if len(stale) > 0 {
		t.Fatalf("action table has entries for methods that do not exist on AgentHarness: %v", stale)
	}
}

// TestActionTableEntriesUseClosedVocabulary verifies that every entry uses
// only the action and effect strings declared in core.yaml. Using a raw
// literal that was not added to the taxonomy will silently fail CEL
// validation at emit time, so catching it here turns a runtime error into a
// compile-safe fixture.
func TestActionTableEntriesUseClosedVocabulary(t *testing.T) {
	validActions := map[string]bool{
		ActionToolCall:         true,
		ActionLLMCall:          true,
		ActionGraphRead:        true,
		ActionGraphWrite:       true,
		ActionPluginQuery:      true,
		ActionDelegate:         true,
		ActionFindingSubmit:    true,
		ActionAuthzDecision:    true,
		ActionMissionLifecycle: true,
	}
	validEffects := map[string]bool{
		EffectRead:    true,
		EffectWrite:   true,
		EffectBoth:    true,
		EffectExecute: true,
		EffectNone:    true,
	}

	for m, e := range DefaultActionTable() {
		if !validActions[e.Action] {
			t.Errorf("entry %s: action %q is not in the closed vocabulary", m, e.Action)
		}
		if !validEffects[e.DefaultEffect] {
			t.Errorf("entry %s: effect %q is not in the closed vocabulary", m, e.DefaultEffect)
		}
	}
}
