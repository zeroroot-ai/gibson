package checkpoint_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/checkpoint"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// createTestPolicy creates a DefaultCheckpointPolicy for testing.
func createTestPolicy(t *testing.T, stateClient *state.StateClient, config checkpoint.PolicyConfig) *checkpoint.DefaultCheckpointPolicy {
	storeConfig := checkpoint.StoreConfig{
		KeyPrefix:  testKeyPrefix,
		DefaultTTL: 24 * time.Hour,
	}

	store := checkpoint.NewRedisCheckpointStore(stateClient, storeConfig)
	return checkpoint.NewCheckpointPolicy(store, config)
}

// TestRetention_FinalOnly tests RetentionFinalOnly mode.
func TestRetention_FinalOnly(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.CompletedRetention = checkpoint.RetentionConfig{
		Mode:     checkpoint.RetentionFinalOnly,
		TTL:      0,
		MaxCount: 0,
	}

	policy := createTestPolicy(t, stateClient, policyConfig)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create 10 checkpoints
	checkpoints := createTestCheckpoints(10, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Verify all checkpoints exist
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 10)

	// Apply retention for completed mission
	err = policy.ApplyRetention(ctx, threadID, checkpoint.MissionStatusCompleted)
	require.NoError(t, err)

	// Should only have the final checkpoint remaining
	list, err = store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 1, "Should only keep final checkpoint")

	// Verify it's the last checkpoint we saved
	lastCheckpoint := checkpoints[len(checkpoints)-1]
	assert.Equal(t, lastCheckpoint.ID, list[0].ID)
}

// TestRetention_All tests RetentionAll mode.
func TestRetention_All(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.FailedRetention = checkpoint.RetentionConfig{
		Mode:     checkpoint.RetentionAll,
		TTL:      0,
		MaxCount: 0,
	}

	policy := createTestPolicy(t, stateClient, policyConfig)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create 10 checkpoints
	checkpoints := createTestCheckpoints(10, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Apply retention for failed mission
	err = policy.ApplyRetention(ctx, threadID, checkpoint.MissionStatusFailed)
	require.NoError(t, err)

	// All checkpoints should remain
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 10, "Should keep all checkpoints for failed missions")
}

// TestRetention_ErrorOnly tests RetentionErrorOnly mode.
func TestRetention_ErrorOnly(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.DefaultMode = checkpoint.RetentionErrorOnly

	policy := createTestPolicy(t, stateClient, policyConfig)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create checkpoints
	checkpoints := createTestCheckpoints(10, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// For completed mission with error_only, should keep only final
	err = policy.ApplyRetention(ctx, threadID, checkpoint.MissionStatusCompleted)
	require.NoError(t, err)

	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 1, "Should keep only final for successful missions")

	// Create more checkpoints for failed mission test
	threadID2 := "test-thread-2"
	checkpoints2 := createTestCheckpoints(10, missionID, threadID2)
	for _, cp := range checkpoints2 {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// For failed mission with error_only, should keep all
	err = policy.ApplyRetention(ctx, threadID2, checkpoint.MissionStatusFailed)
	require.NoError(t, err)

	list2, err := store.ListByThread(ctx, threadID2, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list2, 10, "Should keep all checkpoints for failed missions")
}

// TestRetention_MaxCount tests MaxCount limit.
func TestRetention_MaxCount(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.CompletedRetention = checkpoint.RetentionConfig{
		Mode:     checkpoint.RetentionAll,
		TTL:      0,
		MaxCount: 5, // Keep only 5 most recent
	}

	policy := createTestPolicy(t, stateClient, policyConfig)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create 20 checkpoints
	checkpoints := createTestCheckpoints(20, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Apply retention with MaxCount=5
	err = policy.ApplyRetention(ctx, threadID, checkpoint.MissionStatusCompleted)
	require.NoError(t, err)

	// Should only have 5 checkpoints remaining
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 5, "Should keep only MaxCount checkpoints")

	// Verify we kept the most recent ones
	lastFive := checkpoints[len(checkpoints)-5:]
	keptIDs := make(map[string]bool)
	for _, cp := range list {
		keptIDs[cp.ID] = true
	}

	for _, cp := range lastFive {
		assert.True(t, keptIDs[cp.ID], "Should keep most recent checkpoints")
	}
}

// TestRetention_TTLCleanup tests TTL-based cleanup.
func TestRetention_TTLCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TTL test in short mode")
	}

	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.CompletedRetention = checkpoint.RetentionConfig{
		Mode:     checkpoint.RetentionAll,
		TTL:      2 * time.Second, // Short TTL for testing
		MaxCount: 0,
	}

	policy := createTestPolicy(t, stateClient, policyConfig)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create old checkpoints (simulate by creating and then waiting)
	oldCheckpoints := createTestCheckpoints(3, missionID, threadID)
	for _, cp := range oldCheckpoints {
		// Backdate the checkpoint; recompute checksum because CreatedAt is part
		// of the checksum input, so modifying it after createTestCheckpoints would
		// produce a mismatch on load.
		cp.CreatedAt = time.Now().Add(-5 * time.Second)
		checksum, err := cp.ComputeChecksum()
		require.NoError(t, err)
		cp.Checksum = checksum
		err = store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Create recent checkpoint
	recentCheckpoint := checkpoint.NewCheckpoint(missionID, threadID)
	checksum, _ := recentCheckpoint.ComputeChecksum()
	recentCheckpoint.Checksum = checksum
	err = store.Save(ctx, recentCheckpoint)
	require.NoError(t, err)

	// Verify all checkpoints exist
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 4)

	// Apply TTL-based retention
	err = policy.ApplyRetention(ctx, threadID, checkpoint.MissionStatusCompleted)
	require.NoError(t, err)

	// Old checkpoints should be deleted, but recent one and last one should remain
	list, err = store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(list), 2, "Old checkpoints should be deleted by TTL")

	// Recent checkpoint should be present
	found := false
	for _, cp := range list {
		if cp.ID == recentCheckpoint.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "Recent checkpoint should be retained")
}

// TestRetention_RunningMissionProtection tests that running missions are protected.
func TestRetention_RunningMissionProtection(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.CompletedRetention = checkpoint.RetentionConfig{
		Mode:     checkpoint.RetentionFinalOnly,
		TTL:      0,
		MaxCount: 0,
	}

	policy := createTestPolicy(t, stateClient, policyConfig)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create checkpoints
	checkpoints := createTestCheckpoints(10, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Apply retention for RUNNING mission
	err = policy.ApplyRetention(ctx, threadID, checkpoint.MissionStatusRunning)
	require.NoError(t, err)

	// All checkpoints should remain (running missions are protected)
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 10, "Should not delete checkpoints for running missions")
}

// TestRetention_LabeledMode tests RetentionLabeled mode.
func TestRetention_LabeledMode(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.CompletedRetention = checkpoint.RetentionConfig{
		Mode:     checkpoint.RetentionLabeled,
		TTL:      0,
		MaxCount: 0,
	}

	policy := createTestPolicy(t, stateClient, policyConfig)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create checkpoints - some with labels, some without
	for i := 0; i < 10; i++ {
		cp := checkpoint.NewCheckpoint(missionID, threadID)
		cp.CurrentNodeID = fmt.Sprintf("node-%d", i)

		// Label every 3rd checkpoint
		if i%3 == 0 {
			cp.Label = fmt.Sprintf("milestone-%d", i)
		}

		checksum, _ := cp.ComputeChecksum()
		cp.Checksum = checksum

		err := store.Save(ctx, cp)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	// Apply retention for completed mission
	err = policy.ApplyRetention(ctx, threadID, checkpoint.MissionStatusCompleted)
	require.NoError(t, err)

	// Should keep labeled checkpoints + final checkpoint
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)

	// Labeled: 0, 3, 6, 9 (4 total) + final (9) = should keep labeled ones
	// Since 9 is both labeled and final, we should have 4 checkpoints
	assert.GreaterOrEqual(t, len(list), 4, "Should keep labeled checkpoints")

	// Verify all remaining checkpoints are either labeled or the final one
	for i, cp := range list {
		if i < len(list)-1 {
			// Not the last checkpoint, should be labeled
			assert.NotEmpty(t, cp.Label, "Non-final checkpoint should be labeled")
		}
	}
}

// TestRetention_ShouldCheckpoint tests checkpoint decision logic.
func TestRetention_ShouldCheckpoint(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.AutoCheckpoint = true
	policyConfig.MinCheckpointInterval = 1 * time.Second

	policy := createTestPolicy(t, stateClient, policyConfig)

	// Critical events should always checkpoint
	criticalEvents := []checkpoint.CheckpointEventType{
		checkpoint.CheckpointEventApproval,
		checkpoint.CheckpointEventShutdown,
		checkpoint.CheckpointEventError,
		checkpoint.CheckpointEventBranch,
		checkpoint.CheckpointEventExplicit,
	}

	for _, eventType := range criticalEvents {
		event := checkpoint.NewCheckpointEvent(eventType, "test-node")
		should := policy.ShouldCheckpoint(ctx, event)
		assert.True(t, should, "Should checkpoint for %s", eventType)
	}

	// Super-step with rate limiting
	threadID := "test-thread"
	event := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventSuperStep, "test-node")
	event.Metadata["thread_id"] = threadID

	// First super-step should checkpoint
	should := policy.ShouldCheckpoint(ctx, event)
	assert.True(t, should, "First super-step should checkpoint")

	// Record checkpoint
	policy.RecordCheckpoint(threadID, time.Now())

	// Immediate second super-step should be rate-limited
	should = policy.ShouldCheckpoint(ctx, event)
	assert.False(t, should, "Should be rate-limited")

	// Wait for interval
	time.Sleep(1100 * time.Millisecond)

	// After interval, should checkpoint again
	should = policy.ShouldCheckpoint(ctx, event)
	assert.True(t, should, "Should checkpoint after interval")
}

// TestRetention_AutoCheckpointDisabled tests disabling auto-checkpoint.
func TestRetention_AutoCheckpointDisabled(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	policyConfig := checkpoint.DefaultPolicyConfig()
	policyConfig.AutoCheckpoint = false // Disable auto-checkpoint

	policy := createTestPolicy(t, stateClient, policyConfig)

	// Super-step should not checkpoint when auto-checkpoint is disabled
	event := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventSuperStep, "test-node")
	should := policy.ShouldCheckpoint(ctx, event)
	assert.False(t, should, "Should not auto-checkpoint when disabled")

	// Explicit checkpoint should still work
	explicitEvent := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventExplicit, "test-node")
	should = policy.ShouldCheckpoint(ctx, explicitEvent)
	assert.True(t, should, "Explicit checkpoint should work when auto-checkpoint is disabled")
}
