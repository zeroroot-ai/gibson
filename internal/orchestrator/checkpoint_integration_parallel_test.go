package orchestrator

import (
	"testing"

	"github.com/zero-day-ai/gibson/internal/types"
)

// TestTrackParallelCompletion_WithExpectedTotals — Spec 4 R4.1, R4.4.
//
// Constructs a CheckpointIntegration with WithParallelGroupTotals and asserts
// TrackParallelCompletion returns true exactly once when the expected number
// of nodes report completion.
func TestTrackParallelCompletion_WithExpectedTotals(t *testing.T) {
	groupID := "group-A"
	expected := 8

	ci := NewCheckpointIntegration(
		nil, // checkpointer not exercised on this path
		nil, // policy not exercised
		mustParseID(t, "00000000-0000-0000-0000-000000000001"),
		"thread-1",
		WithParallelGroupTotals(map[string]int{groupID: expected}),
	)

	fired := 0
	for i := 0; i < expected; i++ {
		nodeID := nodeIDForIdx(i)
		if ci.TrackParallelCompletion(groupID, nodeID) {
			fired++
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 fire on the last node; got %d", fired)
	}

	// A late-arriving duplicate completion must NOT re-fire.
	if ci.TrackParallelCompletion(groupID, nodeIDForIdx(expected)) {
		t.Fatal("re-fire after group completion is forbidden (spec R4.4)")
	}
}

// TestTrackParallelCompletion_NoExpectedTotal — when no expected count is
// registered, TrackParallelCompletion always returns false (the orchestrator
// must explicitly call OnParallelGroupComplete in that case).
func TestTrackParallelCompletion_NoExpectedTotal(t *testing.T) {
	ci := NewCheckpointIntegration(
		nil, nil,
		mustParseID(t, "00000000-0000-0000-0000-000000000002"),
		"thread-2",
	)
	for i := 0; i < 4; i++ {
		if ci.TrackParallelCompletion("unknown-group", nodeIDForIdx(i)) {
			t.Fatalf("got auto-fire without expected totals registered (i=%d)", i)
		}
	}
}

// TestSetParallelGroupTotal_Runtime — exercise the runtime registration path.
func TestSetParallelGroupTotal_Runtime(t *testing.T) {
	ci := NewCheckpointIntegration(
		nil, nil,
		mustParseID(t, "00000000-0000-0000-0000-000000000003"),
		"thread-3",
	)

	groupID := "group-runtime"
	// First two completions arrive before the total is known.
	ci.TrackParallelCompletion(groupID, "n0")
	ci.TrackParallelCompletion(groupID, "n1")

	// Operator/orchestrator now knows the total.
	ci.SetParallelGroupTotal(groupID, 3)

	// One more completion — should fire because total=3 and we've seen 3 nodes.
	if !ci.TrackParallelCompletion(groupID, "n2") {
		t.Fatal("expected fire after SetParallelGroupTotal + final completion")
	}
}

func nodeIDForIdx(i int) string {
	return "node-" + string(rune('a'+i))
}

func mustParseID(t *testing.T, s string) types.ID {
	t.Helper()
	id, err := types.ParseID(s)
	if err != nil {
		t.Fatalf("parse id %q: %v", s, err)
	}
	return id
}
