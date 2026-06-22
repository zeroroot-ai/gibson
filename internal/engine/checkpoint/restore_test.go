package checkpoint

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Note: MockCheckpointStore is defined in policy_test.go and reused here

// mockBlobStore is a simple in-memory blob store for testing restore functionality
type mockBlobStore struct {
	blobs map[string][]byte
}

func newMockBlobStore() *mockBlobStore {
	return &mockBlobStore{
		blobs: make(map[string][]byte),
	}
}

func (m *mockBlobStore) Store(ctx context.Context, threadID string, data []byte) (string, error) {
	blobID := "blob_" + threadID + "_" + time.Now().Format("20060102150405")
	m.blobs[blobID] = data
	return blobID, nil
}

func (m *mockBlobStore) Get(ctx context.Context, threadID string, blobID string) ([]byte, error) {
	data, ok := m.blobs[blobID]
	if !ok {
		return nil, ErrBlobNotFound
	}
	return data, nil
}

func (m *mockBlobStore) Delete(ctx context.Context, threadID string, blobID string) error {
	delete(m.blobs, blobID)
	return nil
}

func (m *mockBlobStore) DeleteByThread(ctx context.Context, threadID string) error {
	// Simple implementation for testing
	return nil
}

func (m *mockBlobStore) ShouldStoreAsBlob(size int) bool {
	return int64(size) >= 1048576 // 1MB threshold
}

// Note: MockCheckpointStore already implements the CheckpointStore interface correctly,
// so we can use it directly without an adapter

func TestValidateCheckpointVersion(t *testing.T) {
	tests := []struct {
		name    string
		version int
		wantErr bool
	}{
		{
			name:    "valid version 2 (current)",
			version: CurrentCheckpointVersion,
			wantErr: false,
		},
		{
			name:    "version too old (version 1)",
			version: 1,
			wantErr: true,
		},
		{
			name:    "version too old (version 0)",
			version: 0,
			wantErr: true,
		},
		{
			name:    "version too new (hypothetical version 3)",
			version: 3,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCheckpointVersion(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildPendingQueue(t *testing.T) {
	tests := []struct {
		name       string
		checkpoint *Checkpoint
		want       []string
	}{
		{
			name:       "nil checkpoint",
			checkpoint: nil,
			want:       []string{},
		},
		{
			name: "checkpoint with DAG state",
			checkpoint: &Checkpoint{
				DAGState: &DAGTraversalState{
					PendingNodes: []string{"node1", "node2", "node3"},
				},
			},
			want: []string{"node1", "node2", "node3"},
		},
		{
			name: "checkpoint with pending nodes but no DAG state",
			checkpoint: &Checkpoint{
				PendingNodes: []string{"node4", "node5"},
			},
			want: []string{"node4", "node5"},
		},
		{
			name:       "checkpoint with no pending nodes",
			checkpoint: &Checkpoint{},
			want:       []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildPendingQueue(tt.checkpoint)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIdentifySkippedNodes(t *testing.T) {
	tests := []struct {
		name       string
		checkpoint *Checkpoint
		wantCount  int
	}{
		{
			name:       "nil checkpoint",
			checkpoint: nil,
			wantCount:  0,
		},
		{
			name: "checkpoint with completed nodes",
			checkpoint: &Checkpoint{
				CompletedNodes: map[string]*NodeOutput{
					"node1": {NodeID: "node1", Status: "completed"},
					"node2": {NodeID: "node2", Status: "completed"},
				},
			},
			wantCount: 2,
		},
		{
			name:       "checkpoint with no completed nodes",
			checkpoint: &Checkpoint{},
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IdentifySkippedNodes(tt.checkpoint)
			assert.Len(t, got, tt.wantCount)
		})
	}
}

func TestDefaultStateRestorer_Validate(t *testing.T) {
	missionID := types.NewID()
	threadID := "thread-123"

	tests := []struct {
		name       string
		checkpoint *Checkpoint
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "nil checkpoint",
			checkpoint: nil,
			wantErr:    true,
			errMsg:     "checkpoint is nil",
		},
		{
			name: "missing ID",
			checkpoint: &Checkpoint{
				Version:   CurrentCheckpointVersion,
				ThreadID:  threadID,
				MissionID: missionID,
			},
			wantErr: true,
			errMsg:  "checkpoint missing ID",
		},
		{
			name: "missing thread ID",
			checkpoint: &Checkpoint{
				ID:        "checkpoint-123",
				Version:   CurrentCheckpointVersion,
				MissionID: missionID,
			},
			wantErr: true,
			errMsg:  "checkpoint missing thread ID",
		},
		{
			name: "invalid version",
			checkpoint: &Checkpoint{
				ID:        "checkpoint-123",
				ThreadID:  threadID,
				MissionID: missionID,
				Version:   99,
			},
			wantErr: true,
			errMsg:  "version validation failed",
		},
	}

	restorer := NewStateRestorer(
		NewMockCheckpointStore(),
		newMockBlobStore(),
		NewStateSerializer(),
		NewZstdCompressor(DefaultCompressionConfig()),
		nil, // No encryption for these tests
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := restorer.Validate(tt.checkpoint)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultStateRestorer_Restore(t *testing.T) {
	missionID := types.NewID()
	threadID := "thread-123"

	// Create a valid checkpoint
	checkpoint := NewCheckpoint(missionID, threadID)
	checkpoint.CurrentNodeID = "node-1"
	checkpoint.NodeStates = map[string]*NodeState{
		"node-1": {
			NodeID: "node-1",
			Status: NodeStatusRunning,
		},
	}
	checkpoint.CompletedNodes = map[string]*NodeOutput{}
	checkpoint.PendingNodes = []string{"node-2", "node-3"}

	// Compute checksum
	checksum, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)
	checkpoint.Checksum = checksum

	// Create restorer
	store := NewMockCheckpointStore()
	err = store.SaveCheckpoint(context.Background(), checkpoint)
	require.NoError(t, err)

	restorer := NewStateRestorer(
		store,
		newMockBlobStore(),
		NewStateSerializer(),
		NewZstdCompressor(DefaultCompressionConfig()),
		nil, // No encryption for this test
	)

	// Test restoration
	ctx := context.Background()
	state, err := restorer.Restore(ctx, checkpoint)
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, missionID, state.MissionID)
	assert.Equal(t, threadID, state.ThreadID)
	assert.Equal(t, "node-1", state.CurrentNodeID)
	assert.Len(t, state.PendingQueue, 2)
	assert.Contains(t, state.PendingQueue, "node-2")
	assert.Contains(t, state.PendingQueue, "node-3")
}

func TestDefaultStateRestorer_RestoreLatest(t *testing.T) {
	missionID := types.NewID()
	threadID := "thread-456"

	store := NewMockCheckpointStore()

	// Create multiple checkpoints
	checkpoint1 := NewCheckpoint(missionID, threadID)
	checkpoint1.CreatedAt = time.Now().Add(-2 * time.Hour)
	checksum1, _ := checkpoint1.ComputeChecksum()
	checkpoint1.Checksum = checksum1
	checkpoint1.NodeStates = make(map[string]*NodeState)
	checkpoint1.CompletedNodes = make(map[string]*NodeOutput)

	checkpoint2 := NewCheckpoint(missionID, threadID)
	checkpoint2.CreatedAt = time.Now().Add(-1 * time.Hour)
	checksum2, _ := checkpoint2.ComputeChecksum()
	checkpoint2.Checksum = checksum2
	checkpoint2.NodeStates = make(map[string]*NodeState)
	checkpoint2.CompletedNodes = make(map[string]*NodeOutput)

	checkpoint3 := NewCheckpoint(missionID, threadID)
	checkpoint3.CreatedAt = time.Now()
	checksum3, _ := checkpoint3.ComputeChecksum()
	checkpoint3.Checksum = checksum3
	checkpoint3.NodeStates = make(map[string]*NodeState)
	checkpoint3.CompletedNodes = make(map[string]*NodeOutput)

	require.NoError(t, store.SaveCheckpoint(context.Background(), checkpoint1))
	require.NoError(t, store.SaveCheckpoint(context.Background(), checkpoint2))
	require.NoError(t, store.SaveCheckpoint(context.Background(), checkpoint3))

	restorer := NewStateRestorer(
		store,
		newMockBlobStore(),
		NewStateSerializer(),
		NewZstdCompressor(DefaultCompressionConfig()),
		nil,
	)

	// Restore latest
	ctx := context.Background()
	state, err := restorer.RestoreLatest(ctx, threadID)
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, threadID, state.ThreadID)
}

func TestDefaultStateRestorer_RestoreWithResult(t *testing.T) {
	missionID := types.NewID()
	threadID := "thread-789"

	checkpoint := NewCheckpoint(missionID, threadID)
	checkpoint.CurrentNodeID = "node-1"
	checkpoint.NodeStates = map[string]*NodeState{
		"node-1": {NodeID: "node-1", Status: NodeStatusRunning},
	}
	checkpoint.CompletedNodes = map[string]*NodeOutput{
		"node-0": {NodeID: "node-0", Status: "completed"},
	}
	checkpoint.PendingNodes = []string{"node-2", "node-3"}

	checksum, err := checkpoint.ComputeChecksum()
	require.NoError(t, err)
	checkpoint.Checksum = checksum

	restorer := NewStateRestorer(
		NewMockCheckpointStore(),
		newMockBlobStore(),
		NewStateSerializer(),
		NewZstdCompressor(DefaultCompressionConfig()),
		nil,
	)

	ctx := context.Background()
	result, err := restorer.RestoreWithResult(ctx, checkpoint)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.State)
	assert.NotNil(t, result.Checkpoint)
	assert.Len(t, result.NodesSkipped, 1)
	assert.Contains(t, result.NodesSkipped, "node-0")
	assert.Len(t, result.NodesToExecute, 2)
	assert.Greater(t, result.Duration, time.Duration(0))
}
