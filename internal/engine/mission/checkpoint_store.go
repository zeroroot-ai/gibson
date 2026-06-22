package mission

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// RedisCheckpointStore implements CheckpointStore using Redis for persistence.
// It uses RedisJSON for efficient storage and retrieval of checkpoint data.
type RedisCheckpointStore struct {
	client *state.StateClient
	prefix string
	ttl    time.Duration
}

// NewRedisCheckpointStore creates a new Redis-backed checkpoint store.
// The prefix parameter is used to namespace checkpoint keys in Redis.
// The default TTL is 7 days for checkpoint data.
func NewRedisCheckpointStore(client *state.StateClient) *RedisCheckpointStore {
	return &RedisCheckpointStore{
		client: client,
		prefix: "checkpoint",
		ttl:    7 * 24 * time.Hour, // 7 days default TTL
	}
}

// WithPrefix sets a custom prefix for Redis keys.
// This allows multiple checkpoint stores to coexist in the same Redis instance.
func (s *RedisCheckpointStore) WithPrefix(prefix string) *RedisCheckpointStore {
	s.prefix = prefix
	return s
}

// WithTTL sets a custom TTL for checkpoint data.
// Set to 0 to disable expiration.
func (s *RedisCheckpointStore) WithTTL(ttl time.Duration) *RedisCheckpointStore {
	s.ttl = ttl
	return s
}

// Save persists a checkpoint to Redis using JSON.SET.
// The checkpoint is stored with the key pattern: "checkpoint:{mission_id}"
// An optional TTL can be set to automatically expire old checkpoints.
func (s *RedisCheckpointStore) Save(ctx context.Context, missionID types.ID, checkpoint *Checkpoint) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint cannot be nil")
	}

	if missionID.IsZero() {
		return fmt.Errorf("mission ID cannot be zero")
	}

	// Build the Redis key
	key := s.checkpointKey(missionID)

	// Set checkpoint creation time if not already set
	if checkpoint.CreatedAt.IsZero() {
		checkpoint.CreatedAt = time.Now()
	}

	// Store checkpoint using JSON.SET
	if err := s.client.JSONSet(ctx, key, "$", checkpoint); err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	// Set TTL if configured
	if s.ttl > 0 {
		rdb := s.client.Client()
		if err := rdb.Expire(ctx, key, s.ttl).Err(); err != nil {
			// Log warning but don't fail the save operation
			// The checkpoint is already persisted, TTL is just a cleanup mechanism
			return fmt.Errorf("failed to set checkpoint TTL (checkpoint saved): %w", err)
		}
	}

	return nil
}

// Load retrieves a checkpoint from Redis using JSON.GET.
// Returns nil if no checkpoint exists for the given mission.
func (s *RedisCheckpointStore) Load(ctx context.Context, missionID types.ID) (*Checkpoint, error) {
	if missionID.IsZero() {
		return nil, fmt.Errorf("mission ID cannot be zero")
	}

	// Build the Redis key
	key := s.checkpointKey(missionID)

	// Retrieve checkpoint using JSON.GET
	var checkpoint Checkpoint
	if err := s.client.JSONGet(ctx, key, "$", &checkpoint); err != nil {
		if state.IsNotFound(err) {
			return nil, nil // No checkpoint exists
		}
		return nil, fmt.Errorf("failed to load checkpoint: %w", err)
	}

	return &checkpoint, nil
}

// Delete removes a checkpoint from Redis using JSON.DEL.
// This should be called when a mission completes successfully.
func (s *RedisCheckpointStore) Delete(ctx context.Context, missionID types.ID) error {
	if missionID.IsZero() {
		return fmt.Errorf("mission ID cannot be zero")
	}

	// Build the Redis key
	key := s.checkpointKey(missionID)

	// Delete checkpoint using JSON.DEL
	if err := s.client.JSONDel(ctx, key, "$"); err != nil {
		return fmt.Errorf("failed to delete checkpoint: %w", err)
	}

	return nil
}

// Exists checks if a checkpoint exists for the given mission.
// This is a lightweight operation that doesn't retrieve the full checkpoint data.
func (s *RedisCheckpointStore) Exists(ctx context.Context, missionID types.ID) (bool, error) {
	if missionID.IsZero() {
		return false, fmt.Errorf("mission ID cannot be zero")
	}

	// Build the Redis key
	key := s.checkpointKey(missionID)

	// Use EXISTS command to check if key exists
	rdb := s.client.Client()
	result, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check checkpoint existence: %w", err)
	}

	return result > 0, nil
}

// checkpointKey builds the Redis key for a checkpoint.
// Format: "{prefix}:{mission_id}"
func (s *RedisCheckpointStore) checkpointKey(missionID types.ID) string {
	return fmt.Sprintf("%s:%s", s.prefix, missionID.String())
}

// Ensure RedisCheckpointStore implements CheckpointStore at compile time.
var _ CheckpointStore = (*RedisCheckpointStore)(nil)
