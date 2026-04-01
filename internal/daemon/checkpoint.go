package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/types"
)

// checkpointKeyPrefix is the Redis key prefix for mission checkpoints
const checkpointKeyPrefix = "gibson:checkpoint:"

// DaemonMissionCheckpointer implements MissionCheckpointer for the daemon.
// It checkpoints running missions to Redis during graceful shutdown so they can
// be resumed after restart.
type DaemonMissionCheckpointer struct {
	// redisClient is the Redis client for storing checkpoints
	redisClient redis.UniversalClient

	// activeMissions returns the map of currently running missions
	// This is a function to avoid holding a lock on the daemon's mission map
	activeMissions func() map[string]context.CancelFunc

	// missionStore provides access to mission metadata
	missionStore mission.MissionStore

	// logger for structured logging
	logger *observability.Logger
}

// NewDaemonMissionCheckpointer creates a new mission checkpointer.
func NewDaemonMissionCheckpointer(
	redisClient redis.UniversalClient,
	activeMissions func() map[string]context.CancelFunc,
	missionStore mission.MissionStore,
	logger *observability.Logger,
) *DaemonMissionCheckpointer {
	return &DaemonMissionCheckpointer{
		redisClient:    redisClient,
		activeMissions: activeMissions,
		missionStore:   missionStore,
		logger:         logger,
	}
}

// CheckpointAll checkpoints all currently running missions.
// Returns the number of missions successfully checkpointed.
//
// This method iterates through all active missions and creates a checkpoint
// for each one in Redis. Errors during individual checkpoint operations are
// logged but do not stop the overall process, ensuring best-effort checkpointing.
func (c *DaemonMissionCheckpointer) CheckpointAll(ctx context.Context) (int, error) {
	if c.redisClient == nil {
		return 0, fmt.Errorf("redis client not available")
	}

	// Get snapshot of active missions
	active := c.activeMissions()
	if len(active) == 0 {
		c.logger.Info(ctx, "no active missions to checkpoint")
		return 0, nil
	}

	c.logger.Info(ctx, "checkpointing active missions", "count", len(active))

	checkpointedCount := 0
	for missionIDStr := range active {
		missionID, err := types.ParseID(missionIDStr)
		if err != nil {
			c.logger.Warn(ctx, "invalid mission ID format, skipping",
				"mission_id", missionIDStr,
				"error", err)
			continue
		}

		if err := c.CheckpointMission(ctx, missionID); err != nil {
			c.logger.Warn(ctx, "failed to checkpoint mission",
				"mission_id", missionID,
				"error", err)
			// Continue with other missions
			continue
		}

		checkpointedCount++
	}

	c.logger.Info(ctx, "mission checkpointing complete",
		"checkpointed", checkpointedCount,
		"total", len(active))

	return checkpointedCount, nil
}

// CheckpointMission creates a checkpoint for a specific mission and stores it in Redis.
//
// The checkpoint is stored with key pattern: gibson:checkpoint:{mission_id}
// It contains:
//   - Mission ID and current state
//   - Checkpoint reason: "graceful_shutdown"
//   - Timestamp
//   - Basic node state information
//
// Checkpoints are stored with no expiration - they remain until explicitly deleted
// or until the mission is resumed.
func (c *DaemonMissionCheckpointer) CheckpointMission(ctx context.Context, missionID types.ID) error {
	// Load mission metadata from store
	mis, err := c.missionStore.Get(ctx, missionID)
	if err != nil {
		return fmt.Errorf("failed to load mission: %w", err)
	}

	// Only checkpoint running missions
	if mis.Status != mission.MissionStatusRunning {
		c.logger.Debug(ctx, "skipping non-running mission",
			"mission_id", missionID,
			"status", mis.Status)
		return nil
	}

	// Create checkpoint struct
	checkpoint := orchestrator.Checkpoint{
		ID:         fmt.Sprintf("%s-shutdown-%d", missionID.String(), time.Now().Unix()),
		MissionID:  missionID.String(),
		Label:      "graceful_shutdown",
		CreatedAt:  time.Now(),
		NodeStates: make(map[string]orchestrator.NodeCheckpointState),
		IsImplicit: true, // Auto-created during shutdown
	}

	// For graceful shutdown, we create a minimal checkpoint.
	// The mission will need to restart from the beginning, but we preserve
	// the mission metadata and can track that it was interrupted.
	// Orchestrator integration for mid-execution node state is pending: the
	// orchestrator.Checkpoint struct is populated here with the mission ID and
	// label; finer-grained node states will be added when the orchestrator
	// exposes a RestoreFromCheckpoint callback.
	c.logger.Debug(ctx, "creating graceful-shutdown checkpoint (node-level state pending orchestrator integration)",
		"mission_id", missionID)

	// Serialize checkpoint to JSON
	checkpointJSON, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	// Store checkpoint in Redis with key pattern gibson:checkpoint:{mission_id}
	key := checkpointKeyPrefix + missionID.String()
	if err := c.redisClient.Set(ctx, key, checkpointJSON, 0).Err(); err != nil {
		return fmt.Errorf("failed to store checkpoint to Redis: %w", err)
	}

	c.logger.Info(ctx, "mission checkpointed successfully",
		"mission_id", missionID,
		"checkpoint_id", checkpoint.ID,
		"redis_key", key)

	// Update mission status to paused
	if err := c.missionStore.UpdateStatus(ctx, missionID, mission.MissionStatusPaused); err != nil {
		c.logger.Warn(ctx, "failed to update mission status to paused",
			"mission_id", missionID,
			"error", err)
		// Don't fail the checkpoint operation if status update fails
	}

	return nil
}

// GetCheckpoint retrieves a checkpoint for a specific mission from Redis.
func (c *DaemonMissionCheckpointer) GetCheckpoint(ctx context.Context, missionID types.ID) (*orchestrator.Checkpoint, error) {
	if c.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	key := checkpointKeyPrefix + missionID.String()
	checkpointJSON, err := c.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("no checkpoint found for mission %s", missionID)
		}
		return nil, fmt.Errorf("failed to retrieve checkpoint from Redis: %w", err)
	}

	var checkpoint orchestrator.Checkpoint
	if err := json.Unmarshal([]byte(checkpointJSON), &checkpoint); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}

	return &checkpoint, nil
}

// DeleteCheckpoint removes a checkpoint from Redis.
func (c *DaemonMissionCheckpointer) DeleteCheckpoint(ctx context.Context, missionID types.ID) error {
	if c.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	key := checkpointKeyPrefix + missionID.String()
	if err := c.redisClient.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete checkpoint from Redis: %w", err)
	}

	c.logger.Info(ctx, "checkpoint deleted",
		"mission_id", missionID,
		"redis_key", key)

	return nil
}

// ListCheckpoints returns all mission IDs that have checkpoints in Redis.
func (c *DaemonMissionCheckpointer) ListCheckpoints(ctx context.Context) ([]types.ID, error) {
	if c.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	// Scan for all keys matching the checkpoint pattern
	pattern := checkpointKeyPrefix + "*"
	var cursor uint64
	var missionIDs []types.ID

	for {
		keys, nextCursor, err := c.redisClient.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan Redis for checkpoints: %w", err)
		}

		// Extract mission IDs from keys
		for _, key := range keys {
			// Remove prefix to get mission ID
			missionIDStr := key[len(checkpointKeyPrefix):]
			missionID, err := types.ParseID(missionIDStr)
			if err != nil {
				c.logger.Warn(ctx, "invalid mission ID in checkpoint key",
					"key", key,
					"error", err)
				continue
			}
			missionIDs = append(missionIDs, missionID)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return missionIDs, nil
}
