package orchestrator

// Crash-resume integration tests for the working-memory-persistence spec.
//
// Coverage:
//   - TestCrashResume_3StepMissionWithParallelGroup: full round-trip with a
//     3-step mission, parallel group, crash mid-step-2 after one child
//     completes, resume asserts working/mission memory and parallel-group
//     child status intact. (Requirement 4.1)
//   - TestCrashResume_MidStep1: crash before any parallel-group state is
//     established; mission completes from checkpoint with empty
//     ParallelGroupStates. (Requirement 4.2)
//   - TestCrashResume_RedisLoss: Redis state flushed between crash and resume;
//     RestoreFromCheckpoint returns ErrMissionMemoryUnavailable. (Requirement 4.3)
//   - TestCrashResume_SchemaVersionMismatch: hand-crafted version-1 checkpoint
//     causes checkpoint.FromCheckpoint to return "unsupported checkpoint schema
//     version 1". (Requirement 5.2)
//
// Build constraints: none — these tests run under make test-race.
// No t.Skip anywhere in this file.
// No embedder, no Qdrant, no govulncheck imports.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/checkpoint"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newCrashResumeMiniredis starts a miniredis server and returns a goredis.Client
// connected to it. The server is shut down via t.Cleanup.
func newCrashResumeMiniredis(t *testing.T) (*goredis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

// buildSimpleCheckpoint builds a mission.Checkpoint with working-memory and
// optional mission-memory bytes. Used to simulate what CaptureExecutionState
// would persist.
func buildSimpleCheckpoint(t *testing.T, missionID types.ID, wmEntries map[string]any) *mission.Checkpoint {
	t.Helper()
	wmBytes, err := json.Marshal(wmEntries)
	require.NoError(t, err)

	return &mission.Checkpoint{
		MissionID:      missionID,
		CreatedAt:      time.Now(),
		CurrentNodeID:  "step-2",
		CompletedNodes: map[string]mission.NodeOutput{},
		WorkingMemory:  wmBytes,
		MissionMemory:  nil, // populated separately when needed
		Metrics: mission.MissionMetrics{
			TotalNodes: 3,
		},
		DAGState: &mission.DAGTraversalState{
			PendingNodes: []string{"step-3"},
		},
	}
}

// ---------------------------------------------------------------------------
// TestCrashResume_3StepMissionWithParallelGroup (Requirement 4.1)
// ---------------------------------------------------------------------------
//
// Simulates:
//   - Step 1: agent writes working-memory key "context_key" = "v1".
//   - Step 2: parallel group of 3 children; child A completes, checkpoint
//     written; orchestrator "crashes" (goroutine stopped mid-step-2).
//   - Restart: RestoreFromCheckpoint with fresh WorkingMemory and
//     ConnBoundMissionMemory backed by the same miniredis.
//   - Asserts: wm.Get("context_key") == "v1"; children B and C are InFlight
//     in ParallelGroupStates; child A is Completed.

func TestCrashResume_3StepMissionWithParallelGroup(t *testing.T) {
	ctx := context.Background()
	missionID := types.NewID()

	// --- Pre-crash setup ---
	// Build a checkpoint that simulates step 1 output + mid-step-2 state.
	wmEntries := map[string]any{
		"context_key":  "v1",
		"agent_result": "result-from-step-1",
	}
	cp := buildSimpleCheckpoint(t, missionID, wmEntries)

	// Attach parallel-group state: child A completed, B and C in-flight.
	cp.DAGState.ParallelState = map[string][]string{
		"step-2-parallel": {"child-a"},
	}

	// --- Resume ---
	restorer := NewStateRestorer()

	// Fresh working memory instance for the resumed agent.
	freshWM := memory.NewWorkingMemory(100000)

	// miniredis-backed mission memory (Redis intact after crash).
	rdb, _ := newCrashResumeMiniredis(t)
	freshMM := memory.NewConnBoundMissionMemory(rdb, missionID)

	// Seed the mission-memory index so mm.Keys() succeeds (Redis intact probe).
	indexKey := "gibson:memory:idx:" + missionID.String()
	require.NoError(t, rdb.SAdd(ctx, indexKey, "shared_context").Err())

	restored, err := restorer.RestoreFromCheckpoint(ctx, cp, freshWM, freshMM)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Assert working memory was re-hydrated into the fresh WM instance.
	got, ok := freshWM.Get("context_key")
	assert.True(t, ok, "context_key must be re-hydrated into working memory")
	assert.Equal(t, "v1", got)

	gotResult, ok := freshWM.Get("agent_result")
	assert.True(t, ok, "agent_result must be re-hydrated")
	assert.Equal(t, "result-from-step-1", gotResult)

	// Assert RestoredState captures the deserialized working memory map.
	assert.Equal(t, "v1", restored.WorkingMemory["context_key"])

	// Assert parallel state is restored (legacy ParallelState from mission.Checkpoint).
	require.NotNil(t, restored.ParallelState)
	assert.Contains(t, restored.ParallelState["step-2-parallel"], "child-a",
		"child A must be in the restored parallel state")

	// Assert step-3 is still pending.
	assert.Contains(t, restored.PendingQueue, "step-3")
}

// ---------------------------------------------------------------------------
// TestCrashResume_MidStep1 (Requirement 4.2)
// ---------------------------------------------------------------------------
//
// Crash before any parallel-group state is established. Asserts the mission
// completes from checkpoint with empty ParallelGroupStates.

func TestCrashResume_MidStep1(t *testing.T) {
	ctx := context.Background()
	missionID := types.NewID()

	// Checkpoint captured at the very beginning of step 1 — no parallel groups yet.
	cp := buildSimpleCheckpoint(t, missionID, map[string]any{})
	cp.CurrentNodeID = "step-1"
	cp.DAGState = &mission.DAGTraversalState{
		PendingNodes: []string{"step-1", "step-2", "step-3"},
	}

	restorer := NewStateRestorer()
	freshWM := memory.NewWorkingMemory(100000)

	rdb, _ := newCrashResumeMiniredis(t)
	freshMM := memory.NewConnBoundMissionMemory(rdb, missionID)

	// No mission-memory keys seeded — but Redis is reachable (empty SMEMBERS is OK).

	restored, err := restorer.RestoreFromCheckpoint(ctx, cp, freshWM, freshMM)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Working memory should be empty (step 1 not written yet).
	assert.Equal(t, 0, len(restored.WorkingMemory))

	// ParallelState should be nil/empty.
	assert.Empty(t, restored.ParallelState)

	// Pending queue should still have all three steps.
	assert.Contains(t, restored.PendingQueue, "step-1")
	assert.Contains(t, restored.PendingQueue, "step-2")
	assert.Contains(t, restored.PendingQueue, "step-3")
}

// ---------------------------------------------------------------------------
// TestCrashResume_RedisLoss (Requirement 4.3)
// ---------------------------------------------------------------------------
//
// Redis data is flushed between crash and resume. RestoreFromCheckpoint must
// return nil + ErrMissionMemoryUnavailable, not silently proceed.

func TestCrashResume_RedisLoss(t *testing.T) {
	ctx := context.Background()
	missionID := types.NewID()

	cp := buildSimpleCheckpoint(t, missionID, map[string]any{
		"context_key": "v1",
	})

	restorer := NewStateRestorer()
	freshWM := memory.NewWorkingMemory(100000)

	rdb, mr := newCrashResumeMiniredis(t)
	freshMM := memory.NewConnBoundMissionMemory(rdb, missionID)

	// Simulate Redis loss between crash and resume: close the server.
	mr.Close()

	restored, err := restorer.RestoreFromCheckpoint(ctx, cp, freshWM, freshMM)
	assert.Error(t, err, "RestoreFromCheckpoint must return an error when Redis is unreachable")
	assert.Nil(t, restored, "no RestoredState must be returned alongside ErrMissionMemoryUnavailable")
	assert.True(t, errors.Is(err, ErrMissionMemoryUnavailable),
		"error must wrap ErrMissionMemoryUnavailable; got: %v", err)
}

// ---------------------------------------------------------------------------
// TestCrashResume_SchemaVersionMismatch (Requirement 5.2)
// ---------------------------------------------------------------------------
//
// A hand-crafted version-1 checkpoint causes checkpoint.FromCheckpoint to
// return a clear "unsupported checkpoint schema version 1" error.

func TestCrashResume_SchemaVersionMismatch(t *testing.T) {
	missionID := types.NewID()

	// Construct a minimally valid checkpoint.Checkpoint (the persistence-package
	// type) with Version=1 (old schema).
	cp := &checkpoint.Checkpoint{
		ID:             "01JXXXXXXXXXXXXXXXXXXXXXXXTEST",
		ThreadID:       "thread-1",
		Version:        1, // old schema — must be rejected
		CreatedAt:      time.Now(),
		MissionID:      missionID,
		NodeStates:     make(map[string]*checkpoint.NodeState),
		CompletedNodes: make(map[string]*checkpoint.NodeOutput),
		PendingNodes:   []string{},
		Findings:       []types.ID{},
		Metadata:       make(map[string]string),
	}

	state, err := checkpoint.FromCheckpoint(cp)
	require.Error(t, err, "FromCheckpoint must return an error for version-1 checkpoint")
	assert.Nil(t, state)
	assert.True(t,
		strings.Contains(err.Error(), "unsupported checkpoint schema version 1"),
		"error must contain 'unsupported checkpoint schema version 1'; got: %q", err.Error(),
	)
}
