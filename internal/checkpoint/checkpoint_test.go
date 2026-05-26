package checkpoint

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// createTestCheckpoint creates a test checkpoint with all fields populated.
func createTestCheckpoint() *Checkpoint {
	now := time.Now()
	checkpoint := NewCheckpoint(types.NewID(), "thread-test")

	checkpoint.CurrentNodeID = "node-1"
	checkpoint.ParentID = "parent-checkpoint-123"
	checkpoint.Label = "test-checkpoint"

	// Add node states
	checkpoint.NodeStates["node-1"] = &NodeState{
		NodeID:     "node-1",
		Status:     NodeStatusRunning,
		StartedAt:  &now,
		RetryCount: 0,
		Duration:   5 * time.Second,
	}

	checkpoint.NodeStates["node-2"] = &NodeState{
		NodeID:     "node-2",
		Status:     NodeStatusPending,
		RetryCount: 0,
	}

	// Add completed nodes
	checkpoint.CompletedNodes["node-0"] = &NodeOutput{
		NodeID:      "node-0",
		Status:      "completed",
		Output:      map[string]any{"result": "success"},
		Duration:    10 * time.Second,
		CompletedAt: now,
	}

	// Set pending nodes
	checkpoint.PendingNodes = []string{"node-2", "node-3"}

	// Set memory
	checkpoint.WorkingMemory = []byte(`{"key":"value"}`)
	checkpoint.MissionMemory = []byte(`{"target":"192.168.1.1"}`)

	// Set DAG state
	checkpoint.DAGState = &DAGTraversalState{
		PendingNodes:   []string{"node-2", "node-3"},
		CurrentBranch:  "main",
		ParallelState:  map[string][]string{"group-1": {"node-0"}},
		VisitedNodes:   []string{"node-0", "node-1"},
		ExecutionOrder: []string{"node-0", "node-1"},
	}

	// Add findings
	checkpoint.Findings = []types.ID{"finding-1", "finding-2"}

	// Set metadata
	checkpoint.Metadata["user"] = "test-user"
	checkpoint.Metadata["env"] = "test"

	// Set size and flags
	checkpoint.SizeBytes = 1024
	checkpoint.Compressed = true
	checkpoint.Encrypted = true
	checkpoint.KeyID = "key-123"

	return checkpoint
}

func TestCheckpoint_ComputeChecksum(t *testing.T) {
	t.Parallel()

	checkpoint := createTestCheckpoint()

	checksum, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)
	assert.NotEmpty(t, checksum)

	// Checksum should be 64 chars (SHA256 hex)
	assert.Len(t, checksum, 64)

	// Computing again should give same result
	checksum2, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)
	assert.Equal(t, checksum, checksum2)
}

func TestCheckpoint_VerifyChecksum(t *testing.T) {
	t.Parallel()

	checkpoint := createTestCheckpoint()

	// Compute and set checksum
	checksum, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)
	checkpoint.Checksum = checksum

	// Verify should pass
	err = checkpoint.VerifyChecksum()
	assert.NoError(t, err)
}

func TestCheckpoint_VerifyChecksum_Mismatch(t *testing.T) {
	t.Parallel()

	checkpoint := createTestCheckpoint()

	// Set incorrect checksum
	checkpoint.Checksum = "0000000000000000000000000000000000000000000000000000000000000000"

	// Verify should fail
	err := checkpoint.VerifyChecksum()
	require.Error(t, err)
	assert.Equal(t, ErrChecksumMismatch, err)
}

func TestCheckpoint_VerifyChecksum_Missing(t *testing.T) {
	t.Parallel()

	checkpoint := createTestCheckpoint()
	checkpoint.Checksum = ""

	// Verify should fail with missing checksum
	err := checkpoint.VerifyChecksum()
	require.Error(t, err)
	assert.Equal(t, ErrChecksumMissing, err)
}

func TestCheckpoint_Clone(t *testing.T) {
	t.Parallel()

	original := createTestCheckpoint()
	original.Checksum, _ = original.ComputeChecksum()

	clone := original.Clone()

	// Basic fields
	assert.NotEqual(t, original.ID, clone.ID, "cloned ID should be different")
	assert.Equal(t, original.ThreadID, clone.ThreadID)
	assert.Equal(t, original.ID, clone.ParentID, "parent should reference original")
	assert.Equal(t, original.MissionID, clone.MissionID)
	assert.Equal(t, original.CurrentNodeID, clone.CurrentNodeID)
	assert.Equal(t, original.Version, clone.Version)

	// Maps should be deep copied
	assert.Equal(t, len(original.NodeStates), len(clone.NodeStates))
	assert.Equal(t, len(original.CompletedNodes), len(clone.CompletedNodes))
	assert.Equal(t, len(original.Metadata), len(clone.Metadata))

	// Modify clone's maps shouldn't affect original
	clone.NodeStates["new-node"] = &NodeState{NodeID: "new-node"}
	assert.NotContains(t, original.NodeStates, "new-node")

	// Slices should be deep copied
	assert.Equal(t, original.PendingNodes, clone.PendingNodes)
	clone.PendingNodes = append(clone.PendingNodes, "new-pending")
	assert.NotEqual(t, len(original.PendingNodes), len(clone.PendingNodes))

	// DAG state should be deep copied
	if original.DAGState != nil {
		require.NotNil(t, clone.DAGState)
		assert.Equal(t, original.DAGState.CurrentBranch, clone.DAGState.CurrentBranch)
		assert.Equal(t, original.DAGState.PendingNodes, clone.DAGState.PendingNodes)
	}

	// Flags should be copied
	assert.Equal(t, original.Compressed, clone.Compressed)
	assert.Equal(t, original.Encrypted, clone.Encrypted)
	assert.Equal(t, original.KeyID, clone.KeyID)
}

func TestCheckpoint_NewWithULID(t *testing.T) {
	t.Parallel()

	missionID := types.NewID()
	threadID := "thread-456"

	checkpoint := NewCheckpoint(missionID, threadID)

	// Verify ID is set and looks like ULID (26 chars)
	assert.NotEmpty(t, checkpoint.ID)
	assert.Len(t, checkpoint.ID, 26)

	// Verify basic fields
	assert.Equal(t, missionID, checkpoint.MissionID)
	assert.Equal(t, threadID, checkpoint.ThreadID)
	assert.Equal(t, CurrentCheckpointVersion, checkpoint.Version)

	// Verify initialized maps
	assert.NotNil(t, checkpoint.NodeStates)
	assert.NotNil(t, checkpoint.CompletedNodes)
	assert.NotNil(t, checkpoint.Metadata)

	// Verify initialized slices
	assert.NotNil(t, checkpoint.PendingNodes)
	assert.NotNil(t, checkpoint.Findings)

	// Verify timestamp is recent
	assert.WithinDuration(t, time.Now(), checkpoint.CreatedAt, time.Second)
}

func TestCheckpoint_NewWithULID_UniqueIDs(t *testing.T) {
	t.Parallel()

	missionID := types.NewID()
	threadID := "thread-456"

	// Create multiple checkpoints
	checkpoint1 := NewCheckpoint(missionID, threadID)
	checkpoint2 := NewCheckpoint(missionID, threadID)
	checkpoint3 := NewCheckpoint(missionID, threadID)

	// IDs should all be different
	assert.NotEqual(t, checkpoint1.ID, checkpoint2.ID)
	assert.NotEqual(t, checkpoint2.ID, checkpoint3.ID)
	assert.NotEqual(t, checkpoint1.ID, checkpoint3.ID)

	// IDs should be lexicographically sortable (ULID property)
	assert.True(t, checkpoint1.ID < checkpoint2.ID || checkpoint2.ID < checkpoint1.ID)
}

func TestCheckpoint_ComputeSize(t *testing.T) {
	t.Parallel()

	checkpoint := createTestCheckpoint()

	size, err := checkpoint.ComputeSize()
	require.NoError(t, err)
	assert.Greater(t, size, int64(0))

	// Size should be consistent
	size2, err := checkpoint.ComputeSize()
	require.NoError(t, err)
	assert.Equal(t, size, size2)
}

func TestCheckpoint_WithLabel(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")

	result := checkpoint.WithLabel("pre-exploit")

	assert.Equal(t, "pre-exploit", checkpoint.Label)
	assert.Equal(t, checkpoint, result, "should return self for chaining")
}

func TestCheckpoint_WithMetadata(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")

	result := checkpoint.WithMetadata("key1", "value1")
	checkpoint.WithMetadata("key2", "value2")

	assert.Equal(t, "value1", checkpoint.Metadata["key1"])
	assert.Equal(t, "value2", checkpoint.Metadata["key2"])
	assert.Equal(t, checkpoint, result, "should return self for chaining")
}

func TestCheckpoint_WithMetadata_Chaining(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")

	checkpoint.
		WithLabel("test-label").
		WithMetadata("env", "prod").
		WithMetadata("user", "admin")

	assert.Equal(t, "test-label", checkpoint.Label)
	assert.Equal(t, "prod", checkpoint.Metadata["env"])
	assert.Equal(t, "admin", checkpoint.Metadata["user"])
}

func TestNodeStatus_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   NodeStatus
		expected string
	}{
		{NodeStatusPending, "pending"},
		{NodeStatusRunning, "running"},
		{NodeStatusCompleted, "completed"},
		{NodeStatusFailed, "failed"},
		{NodeStatusSkipped, "skipped"},
		{NodeStatusCancelled, "cancelled"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestNodeStatus_IsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status     NodeStatus
		isTerminal bool
	}{
		{NodeStatusPending, false},
		{NodeStatusRunning, false},
		{NodeStatusCompleted, true},
		{NodeStatusFailed, true},
		{NodeStatusSkipped, true},
		{NodeStatusCancelled, true},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			assert.Equal(t, tt.isTerminal, tt.status.IsTerminal())
		})
	}
}

func TestCheckpoint_CloneWithNilFields(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")
	checkpoint.DAGState = nil
	checkpoint.InProgressNode = nil
	checkpoint.ApprovalState = nil

	clone := checkpoint.Clone()

	assert.Nil(t, clone.DAGState)
	assert.Nil(t, clone.InProgressNode)
	assert.Nil(t, clone.ApprovalState)
}

func TestCheckpoint_CloneWithInProgressNode(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")
	now := time.Now()

	checkpoint.InProgressNode = &InProgressNodeState{
		NodeID:        "node-1",
		StartedAt:     now,
		RetryCount:    2,
		PartialOutput: map[string]any{"progress": 50},
		Elapsed:       30 * time.Second,
	}

	clone := checkpoint.Clone()

	require.NotNil(t, clone.InProgressNode)
	assert.Equal(t, checkpoint.InProgressNode.NodeID, clone.InProgressNode.NodeID)
	assert.Equal(t, checkpoint.InProgressNode.RetryCount, clone.InProgressNode.RetryCount)
	assert.Equal(t, checkpoint.InProgressNode.Elapsed, clone.InProgressNode.Elapsed)

	// Modify clone shouldn't affect original
	clone.InProgressNode.PartialOutput["new_key"] = "new_value"
	assert.NotContains(t, checkpoint.InProgressNode.PartialOutput, "new_key")
}

func TestCheckpoint_CloneWithComplexDAGState(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")

	checkpoint.DAGState = &DAGTraversalState{
		PendingNodes:  []string{"node-1", "node-2", "node-3"},
		CurrentBranch: "feature-branch",
		// ParallelState is deprecated (json:"-"); use ParallelGroupStates instead.
		ParallelGroupStates: map[string]ParallelGroupState{
			"group-1": {
				GroupID: "group-1",
				Children: map[string]ChildStatus{
					"node-a": ChildStatusCompleted,
					"node-b": ChildStatusInFlight,
				},
			},
			"group-2": {
				GroupID: "group-2",
				Children: map[string]ChildStatus{
					"node-c": ChildStatusCompleted,
				},
			},
		},
		VisitedNodes:   []string{"node-0"},
		ExecutionOrder: []string{"node-0"},
	}

	clone := checkpoint.Clone()

	require.NotNil(t, clone.DAGState)
	assert.Equal(t, checkpoint.DAGState.CurrentBranch, clone.DAGState.CurrentBranch)
	assert.Equal(t, checkpoint.DAGState.PendingNodes, clone.DAGState.PendingNodes)

	// Deep copy verification: mutating the clone must not affect the original.
	cloneGroup1 := clone.DAGState.ParallelGroupStates["group-1"]
	cloneGroup1.Children["node-d"] = ChildStatusPending
	clone.DAGState.ParallelGroupStates["group-1"] = cloneGroup1

	// Original group-1 must still have 2 children.
	assert.Equal(t, 2, len(checkpoint.DAGState.ParallelGroupStates["group-1"].Children),
		"mutating clone must not affect original DAGState.ParallelGroupStates")
}

func TestCheckpoint_EmptyMetadata(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")

	// Metadata should be initialized but empty
	assert.NotNil(t, checkpoint.Metadata)
	assert.Len(t, checkpoint.Metadata, 0)

	// WithMetadata should work on empty metadata
	checkpoint.WithMetadata("key", "value")
	assert.Equal(t, "value", checkpoint.Metadata["key"])
}

func TestCheckpoint_ComputeChecksumChanges(t *testing.T) {
	t.Parallel()

	checkpoint := createTestCheckpoint()

	checksum1, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)

	// Modify checkpoint
	checkpoint.CurrentNodeID = "different-node"

	checksum2, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)

	// Checksums should be different
	assert.NotEqual(t, checksum1, checksum2, "checksum should change when data changes")
}

func TestCheckpoint_ComputeChecksumIgnoresSizeAndChecksum(t *testing.T) {
	t.Parallel()

	checkpoint := createTestCheckpoint()
	checkpoint.SizeBytes = 1000
	checkpoint.Checksum = ""

	checksum1, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)

	// Change size and checksum (these should be ignored)
	checkpoint.SizeBytes = 2000
	checkpoint.Checksum = "different-checksum"

	checksum2, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)

	// Checksums should be the same (size and checksum fields are excluded)
	assert.Equal(t, checksum1, checksum2, "size and checksum fields should not affect computed checksum")
}

func TestCheckpoint_LargeObjectRefs(t *testing.T) {
	t.Parallel()

	checkpoint := NewCheckpoint(types.NewID(), "thread-test")

	// Add large object references
	checkpoint.LargeObjectRefs = map[string]string{
		"logs":       "s3://bucket/mission-123/logs.tar.gz",
		"artifacts":  "redis://artifacts:node-1",
		"large_data": "blob://storage/data",
	}

	clone := checkpoint.Clone()

	// Verify refs are copied
	assert.Equal(t, checkpoint.LargeObjectRefs, clone.LargeObjectRefs)

	// Modify clone shouldn't affect original
	clone.LargeObjectRefs["new_ref"] = "s3://new"
	assert.NotContains(t, checkpoint.LargeObjectRefs, "new_ref")
}

// Benchmark tests
func BenchmarkCheckpoint_ComputeChecksum(b *testing.B) {
	checkpoint := createTestCheckpoint()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := checkpoint.ComputeChecksum()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckpoint_VerifyChecksum(b *testing.B) {
	checkpoint := createTestCheckpoint()
	checksum, _ := checkpoint.ComputeChecksum()
	checkpoint.Checksum = checksum

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := checkpoint.VerifyChecksum()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckpoint_Clone(b *testing.B) {
	checkpoint := createTestCheckpoint()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = checkpoint.Clone()
	}
}

func BenchmarkCheckpoint_ComputeSize(b *testing.B) {
	checkpoint := createTestCheckpoint()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := checkpoint.ComputeSize()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewCheckpoint(b *testing.B) {
	missionID := types.NewID()
	threadID := "thread-test"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = NewCheckpoint(missionID, threadID)
	}
}
