package checkpoint

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestFromCheckpoint_RejectsVersion1 verifies that FromCheckpoint returns a
// clear error when presented with a version-1 checkpoint (schema version this
// daemon no longer supports).
func TestFromCheckpoint_RejectsVersion1(t *testing.T) {
	missionID := types.NewID()

	// Build a minimally valid checkpoint with Version=1.
	cp := &Checkpoint{
		ID:             "01JXXXXXXXXXXXXXXXXXXXXXXXTEST",
		ThreadID:       "thread-1",
		Version:        1, // old schema
		CreatedAt:      time.Now(),
		MissionID:      missionID,
		NodeStates:     make(map[string]*NodeState),
		CompletedNodes: make(map[string]*NodeOutput),
		PendingNodes:   []string{},
		Findings:       []types.ID{},
		Metadata:       make(map[string]string),
	}

	state, err := FromCheckpoint(cp)
	require.Error(t, err, "FromCheckpoint must return an error for version 1")
	assert.Nil(t, state, "FromCheckpoint must return nil state for unsupported version")
	assert.True(t,
		strings.Contains(err.Error(), "unsupported checkpoint schema version 1"),
		"error must contain 'unsupported checkpoint schema version 1', got: %q", err.Error(),
	)
	assert.True(t,
		strings.Contains(err.Error(), "drain in-flight missions before upgrading"),
		"error must contain drain-before-upgrade instruction, got: %q", err.Error(),
	)
}

// TestFromCheckpoint_AcceptsVersion2 verifies that FromCheckpoint succeeds for
// a checkpoint whose version matches CurrentCheckpointVersion (2).
func TestFromCheckpoint_AcceptsVersion2(t *testing.T) {
	missionID := types.NewID()

	cp := &Checkpoint{
		ID:             "01JXXXXXXXXXXXXXXXXXXXXXXXTEST",
		ThreadID:       "thread-2",
		Version:        CurrentCheckpointVersion, // = 2
		CreatedAt:      time.Now(),
		MissionID:      missionID,
		NodeStates:     make(map[string]*NodeState),
		CompletedNodes: make(map[string]*NodeOutput),
		PendingNodes:   []string{},
		Findings:       []types.ID{},
		Metadata:       make(map[string]string),
	}

	state, err := FromCheckpoint(cp)
	require.NoError(t, err, "FromCheckpoint must succeed for version 2")
	require.NotNil(t, state)
	assert.Equal(t, missionID, state.MissionID)
}

// TestNewCheckpoint_EmitsVersion2 verifies that NewCheckpoint always sets
// Version to CurrentCheckpointVersion (2), never an older value.
func TestNewCheckpoint_EmitsVersion2(t *testing.T) {
	missionID := types.NewID()
	cp := NewCheckpoint(missionID, "thread-3")

	require.NotNil(t, cp)
	assert.Equal(t, CurrentCheckpointVersion, cp.Version,
		"NewCheckpoint must emit Version=%d", CurrentCheckpointVersion)
}
