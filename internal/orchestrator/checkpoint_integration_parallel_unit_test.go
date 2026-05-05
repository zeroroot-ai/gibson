package orchestrator

import (
	"testing"

	"github.com/zero-day-ai/gibson/internal/types"
)

// TestParallelSidecar_Auto exercises the auto-fire helper directly, sidestepping
// the in-struct TrackParallelCompletion wiring that may not be reachable
// without a full integration. Spec: mission-checkpointing R4.1, R4.4.
func TestParallelSidecar_Auto(t *testing.T) {
	id, err := types.ParseID("00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	ci := NewCheckpointIntegration(nil, nil, id, "thread-1",
		WithParallelGroupTotals(map[string]int{"g1": 4}))

	// Underflow: not yet at 4 nodes.
	if ci.trackParallelCompletionAuto("g1", 1) {
		t.Fatal("auto-fire too early")
	}
	if ci.trackParallelCompletionAuto("g1", 3) {
		t.Fatal("auto-fire too early at 3")
	}

	// Reaches the threshold.
	if !ci.trackParallelCompletionAuto("g1", 4) {
		t.Fatal("expected auto-fire at 4")
	}

	// Already fired — must not re-fire.
	if ci.trackParallelCompletionAuto("g1", 5) {
		t.Fatal("re-fire forbidden by R4.4")
	}
}

// TestParallelSidecar_NoTotalRegistered — auto-fire is suppressed when no
// expected total is registered; the orchestrator must invoke
// OnParallelGroupComplete explicitly.
func TestParallelSidecar_NoTotalRegistered(t *testing.T) {
	id, err := types.ParseID("00000000-0000-0000-0000-000000000002")
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	ci := NewCheckpointIntegration(nil, nil, id, "thread-2")

	if ci.trackParallelCompletionAuto("unknown", 100) {
		t.Fatal("auto-fire without registered total is forbidden")
	}
}

// TestParallelSidecar_SetParallelGroupTotal — the runtime registration path.
func TestParallelSidecar_SetParallelGroupTotal(t *testing.T) {
	id, err := types.ParseID("00000000-0000-0000-0000-000000000003")
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	ci := NewCheckpointIntegration(nil, nil, id, "thread-3")

	ci.SetParallelGroupTotal("dyn-group", 3)
	if ci.trackParallelCompletionAuto("dyn-group", 2) {
		t.Fatal("fire too early after SetParallelGroupTotal")
	}
	if !ci.trackParallelCompletionAuto("dyn-group", 3) {
		t.Fatal("expected fire after reaching dynamic total")
	}
}
