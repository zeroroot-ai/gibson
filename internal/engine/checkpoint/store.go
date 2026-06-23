package checkpoint

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// CheckpointStore defines the unified interface for checkpoint storage operations.
// This interface combines requirements from policy.go, threaded_checkpointer.go, and restore.go.
// Implementations must provide atomic, thread-safe operations for checkpoint persistence.
type CheckpointStore interface {
	// Core checkpoint operations

	// SaveCheckpoint persists a checkpoint to storage.
	SaveCheckpoint(ctx context.Context, checkpoint *Checkpoint) error

	// GetCheckpoint retrieves a checkpoint by ID.
	GetCheckpoint(ctx context.Context, checkpointID string) (*Checkpoint, error)

	// Load is an alias for GetCheckpoint for backward compatibility.
	Load(ctx context.Context, checkpointID string) (*Checkpoint, error)

	// ListCheckpoints lists checkpoints for a thread with pagination options.
	ListCheckpoints(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error)

	// ListByThread is an alias for ListCheckpoints.
	ListByThread(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error)

	// GetLatestCheckpoint retrieves the most recent checkpoint for a thread.
	GetLatestCheckpoint(ctx context.Context, threadID string) (*Checkpoint, error)

	// GetLatest is an alias for GetLatestCheckpoint for backward compatibility.
	GetLatest(ctx context.Context, threadID string) (*Checkpoint, error)

	// GetLatestByThread is another alias for GetLatestCheckpoint.
	GetLatestByThread(ctx context.Context, threadID string) (*Checkpoint, error)

	// DeleteCheckpoint deletes a checkpoint by ID.
	DeleteCheckpoint(ctx context.Context, checkpointID string) error

	// DeleteThreadCheckpoints deletes all checkpoints for a thread.
	DeleteThreadCheckpoints(ctx context.Context, threadID string) error

	// DeleteThread is an alias for DeleteThreadCheckpoints (required by threaded_checkpointer.go).
	DeleteThread(ctx context.Context, threadID string) error

	// Additional operations required by policy.go

	// Save is an alias for SaveCheckpoint.
	Save(ctx context.Context, checkpoint *Checkpoint) error

	// Delete is an alias for DeleteCheckpoint.
	Delete(ctx context.Context, checkpointID string) error

	// DeleteMany removes multiple checkpoints in a single operation.
	DeleteMany(ctx context.Context, checkpointIDs []string) error

	// Thread operations (required by threaded_checkpointer.go)

	// SaveThread persists thread metadata.
	SaveThread(ctx context.Context, thread *Thread) error

	// GetThread retrieves thread metadata.
	GetThread(ctx context.Context, threadID string) (*Thread, error)

	// ListThreads retrieves all threads for a mission.
	ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error)
}

// ListOptions configures pagination and ordering for checkpoint listing.
// This is used internally for backwards compatibility with older code.
type ListOptions struct {
	// Limit specifies the maximum number of checkpoints to return.
	Limit int

	// Offset is the number of checkpoints to skip (for pagination).
	Offset int

	// Order specifies sort order using SortOrder constants.
	Order SortOrder
}

// SortOrder specifies the sort direction for list operations.
type SortOrder int

const (
	// SortOrderAscending sorts results in ascending order (oldest first).
	SortOrderAscending SortOrder = iota

	// SortOrderDescending sorts results in descending order (newest first).
	SortOrderDescending
)

// StoreConfig configures the checkpoint store behavior.
type StoreConfig struct {
	// KeyPrefix is the Redis key prefix for all checkpoint data.
	// Default: "gibson"
	KeyPrefix string

	// DefaultTTL is the default TTL for checkpoints.
	// Use 0 to disable automatic expiration.
	// Default: 7 days
	DefaultTTL time.Duration
}

// RedisCheckpointStore implements both CheckpointStore and ThreadStore using Redis.
// It uses RedisJSON for document storage and sorted sets for time-ordered indexes.
//
// Redis key patterns:
//   - Thread: gibson:thread:{mission_id}:{thread_id}
//   - Thread index: gibson:thread:index:{mission_id} (sorted set by creation time)
//   - Checkpoint: gibson:checkpoint:{thread_id}:{checkpoint_id}
//   - Checkpoint index: gibson:checkpoint:index:{thread_id} (sorted set by creation time)
//   - Latest: gibson:checkpoint:latest:{thread_id} (string)
//
// All operations are atomic within a single key. Cross-key operations use
// pipelining for efficiency but are not transactional in cluster mode.
type RedisCheckpointStore struct {
	client *state.StateClient
	config StoreConfig
}

// NewRedisCheckpointStore creates a new Redis-backed checkpoint store.
// If config's KeyPrefix is empty, "gibson" is used.
// If config's DefaultTTL is 0, 7 days is used.
func NewRedisCheckpointStore(client *state.StateClient, config StoreConfig) *RedisCheckpointStore {
	// Apply defaults if needed
	if config.KeyPrefix == "" {
		config.KeyPrefix = "gibson"
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 7 * 24 * time.Hour
	}

	return &RedisCheckpointStore{
		client: client,
		config: config,
	}
}

// Core CheckpointStore interface methods

// Save persists a checkpoint to Redis with optional TTL.
func (s *RedisCheckpointStore) Save(ctx context.Context, checkpoint *Checkpoint) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint cannot be nil")
	}
	if checkpoint.ID == "" {
		return fmt.Errorf("checkpoint ID cannot be empty")
	}
	if checkpoint.ThreadID == "" {
		return fmt.Errorf("checkpoint thread ID cannot be empty")
	}

	// Compute checksum if not set
	if checkpoint.Checksum == "" {
		checksum, err := checkpoint.ComputeChecksum()
		if err != nil {
			return fmt.Errorf("failed to compute checksum: %w", err)
		}
		checkpoint.Checksum = checksum
	}

	// Compute size if not set
	if checkpoint.SizeBytes == 0 {
		size, err := checkpoint.ComputeSize()
		if err != nil {
			return fmt.Errorf("failed to compute size: %w", err)
		}
		checkpoint.SizeBytes = size
	}

	// Build Redis keys
	checkpointKey := s.checkpointKey(checkpoint.ThreadID, checkpoint.ID)
	indexKey := s.checkpointIndexKey(checkpoint.ThreadID)
	latestKey := s.checkpointLatestKey(checkpoint.ThreadID)

	rdb := s.client.Client()

	// Store checkpoint document using JSON.SET
	if err := s.client.JSONSet(ctx, checkpointKey, "$", checkpoint); err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	// Use pipeline for index updates
	pipe := rdb.Pipeline()

	// Set TTL if configured
	if s.config.DefaultTTL > 0 {
		pipe.Expire(ctx, checkpointKey, s.config.DefaultTTL)
	}

	// Add to sorted set index (score = timestamp as Unix nano)
	score := float64(checkpoint.CreatedAt.UnixNano())
	pipe.ZAdd(ctx, indexKey, redis.Z{
		Score:  score,
		Member: checkpoint.ID,
	})

	// Write reverse index: checkpointID → threadID so Load/GetCheckpoint can
	// resolve the full document without the caller supplying the thread ID.
	ridKey := s.checkpointRidKey(checkpoint.ID)
	pipe.Set(ctx, ridKey, checkpoint.ThreadID, s.config.DefaultTTL)

	// Update latest pointer
	pipe.Set(ctx, latestKey, checkpoint.ID, 0)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update checkpoint indexes: %w", err)
	}

	return nil
}

// Load retrieves a checkpoint by ID using the reverse index.
// The reverse index (written by Save) maps checkpointID → threadID so the
// full document can be fetched without the caller supplying the thread ID.
func (s *RedisCheckpointStore) Load(ctx context.Context, checkpointID string) (*Checkpoint, error) {
	if checkpointID == "" {
		return nil, fmt.Errorf("checkpoint ID cannot be empty")
	}

	// Resolve thread ID via the reverse index.
	rdb := s.client.Client()
	threadID, err := rdb.Get(ctx, s.checkpointRidKey(checkpointID)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("failed to read checkpoint reverse index: %w", err)
	}

	checkpointKey := s.checkpointKey(threadID, checkpointID)
	var checkpoint Checkpoint
	if err := s.client.JSONGet(ctx, checkpointKey, "$", &checkpoint); err != nil {
		if state.IsNotFound(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("failed to load checkpoint: %w", err)
	}

	return &checkpoint, nil
}

// ListByThread is an alias for ListCheckpoints.
func (s *RedisCheckpointStore) ListByThread(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error) {
	return s.ListCheckpoints(ctx, threadID, opts)
}

// Delete removes a checkpoint by ID. The reverse index written by Save maps
// checkpointID → threadID so the caller does not need to supply the thread ID.
func (s *RedisCheckpointStore) Delete(ctx context.Context, checkpointID string) error {
	if checkpointID == "" {
		return fmt.Errorf("checkpoint ID cannot be empty")
	}

	// Resolve thread ID via the reverse index (same pattern as Load).
	rdb := s.client.Client()
	threadID, err := rdb.Get(ctx, s.checkpointRidKey(checkpointID)).Result()
	if err != nil {
		if err == redis.Nil {
			// Already gone — treat as a no-op.
			return nil
		}
		return fmt.Errorf("failed to read checkpoint reverse index: %w", err)
	}

	checkpointKey := s.checkpointKey(threadID, checkpointID)
	indexKey := s.checkpointIndexKey(threadID)
	ridKey := s.checkpointRidKey(checkpointID)

	pipe := rdb.Pipeline()
	// Delete the document, remove from the sorted set, and delete the reverse-index entry.
	pipe.Del(ctx, checkpointKey)
	pipe.ZRem(ctx, indexKey, checkpointID)
	pipe.Del(ctx, ridKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete checkpoint %s: %w", checkpointID, err)
	}

	return nil
}

// DeleteMany removes multiple checkpoints in a single operation.
func (s *RedisCheckpointStore) DeleteMany(ctx context.Context, checkpointIDs []string) error {
	if len(checkpointIDs) == 0 {
		return nil
	}

	for _, id := range checkpointIDs {
		if err := s.Delete(ctx, id); err != nil {
			return fmt.Errorf("failed to delete checkpoint %s: %w", id, err)
		}
	}
	return nil
}

// GetLatest retrieves the most recent checkpoint for a thread.
func (s *RedisCheckpointStore) GetLatest(ctx context.Context, threadID string) (*Checkpoint, error) {
	if threadID == "" {
		return nil, fmt.Errorf("thread ID cannot be empty")
	}

	latestKey := s.checkpointLatestKey(threadID)
	rdb := s.client.Client()

	// Get the latest checkpoint ID
	checkpointID, err := rdb.Get(ctx, latestKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("failed to get latest checkpoint ID: %w", err)
	}

	// Fetch the checkpoint document
	checkpointKey := s.checkpointKey(threadID, checkpointID)
	var checkpoint Checkpoint
	if err := s.client.JSONGet(ctx, checkpointKey, "$", &checkpoint); err != nil {
		if state.IsNotFound(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("failed to load checkpoint: %w", err)
	}

	// Verify checksum
	if err := checkpoint.VerifyChecksum(); err != nil {
		return nil, fmt.Errorf("checkpoint failed checksum verification: %w", err)
	}

	return &checkpoint, nil
}

// Extended operations (aliases and additional methods)

// SaveCheckpoint is an alias for Save (required by threaded_checkpointer.go).
func (s *RedisCheckpointStore) SaveCheckpoint(ctx context.Context, checkpoint *Checkpoint) error {
	return s.Save(ctx, checkpoint)
}

// GetCheckpoint is an alias for Load (required by threaded_checkpointer.go).
func (s *RedisCheckpointStore) GetCheckpoint(ctx context.Context, checkpointID string) (*Checkpoint, error) {
	return s.Load(ctx, checkpointID)
}

// ListCheckpoints lists checkpoints for a thread with pagination options.
func (s *RedisCheckpointStore) ListCheckpoints(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error) {
	if threadID == "" {
		return nil, fmt.Errorf("thread ID cannot be empty")
	}

	indexKey := s.checkpointIndexKey(threadID)
	rdb := s.client.Client()

	// Determine limit and offset
	limit := opts.Limit
	if limit == 0 {
		limit = 100 // Default limit
	}
	offset := opts.Offset

	// Query sorted set based on order
	var checkpointIDs []string
	var err error

	start := int64(offset)
	stop := int64(offset + limit - 1)

	if opts.Ascending {
		// Ascending order (oldest first)
		checkpointIDs, err = rdb.ZRange(ctx, indexKey, start, stop).Result()
	} else {
		// Descending order (newest first) - default
		checkpointIDs, err = rdb.ZRevRange(ctx, indexKey, start, stop).Result()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query checkpoint index: %w", err)
	}

	if len(checkpointIDs) == 0 {
		return []*Checkpoint{}, nil
	}

	// Fetch checkpoint documents
	checkpoints := make([]*Checkpoint, 0, len(checkpointIDs))
	for _, checkpointID := range checkpointIDs {
		checkpointKey := s.checkpointKey(threadID, checkpointID)

		var checkpoint Checkpoint
		if err := s.client.JSONGet(ctx, checkpointKey, "$", &checkpoint); err != nil {
			if state.IsNotFound(err) {
				// Checkpoint was deleted but index wasn't updated - skip it
				continue
			}
			return nil, fmt.Errorf("failed to load checkpoint %s: %w", checkpointID, err)
		}

		// Verify checksum
		if err := checkpoint.VerifyChecksum(); err != nil {
			return nil, fmt.Errorf("checkpoint %s failed checksum verification: %w", checkpointID, err)
		}

		checkpoints = append(checkpoints, &checkpoint)
	}

	return checkpoints, nil
}

// GetLatestCheckpoint is an alias for GetLatest (required by threaded_checkpointer.go).
func (s *RedisCheckpointStore) GetLatestCheckpoint(ctx context.Context, threadID string) (*Checkpoint, error) {
	return s.GetLatest(ctx, threadID)
}

// GetLatestByThread is another alias for GetLatest (required by threaded_checkpointer.go).
func (s *RedisCheckpointStore) GetLatestByThread(ctx context.Context, threadID string) (*Checkpoint, error) {
	return s.GetLatest(ctx, threadID)
}

// DeleteCheckpoint is an alias for Delete (required by threaded_checkpointer.go).
func (s *RedisCheckpointStore) DeleteCheckpoint(ctx context.Context, checkpointID string) error {
	return s.Delete(ctx, checkpointID)
}

// DeleteThreadCheckpoints deletes all checkpoints for a thread.
func (s *RedisCheckpointStore) DeleteThreadCheckpoints(ctx context.Context, threadID string) error {
	if threadID == "" {
		return fmt.Errorf("thread ID cannot be empty")
	}

	indexKey := s.checkpointIndexKey(threadID)
	latestKey := s.checkpointLatestKey(threadID)
	rdb := s.client.Client()

	// Get all checkpoint IDs from the index
	checkpointIDs, err := rdb.ZRange(ctx, indexKey, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("failed to list checkpoints: %w", err)
	}

	if len(checkpointIDs) == 0 {
		// No checkpoints to delete
		return nil
	}

	// Build list of keys to delete
	keys := make([]string, 0, len(checkpointIDs)+2)
	for _, checkpointID := range checkpointIDs {
		keys = append(keys, s.checkpointKey(threadID, checkpointID))
	}
	keys = append(keys, indexKey, latestKey)

	// Delete all keys
	if err := rdb.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("failed to delete checkpoints: %w", err)
	}

	return nil
}

// Thread management operations
// RedisCheckpointStore also implements ThreadStore from thread_manager.go

// SaveThread persists thread metadata to storage.
func (s *RedisCheckpointStore) SaveThread(ctx context.Context, thread *Thread) error {
	if thread == nil {
		return fmt.Errorf("thread cannot be nil")
	}
	if thread.ID == "" {
		return fmt.Errorf("thread ID cannot be empty")
	}
	if thread.MissionID.IsZero() {
		return fmt.Errorf("thread mission ID cannot be zero")
	}

	// Update timestamp
	thread.UpdatedAt = time.Now()

	// Build Redis keys
	threadKey := s.threadKey(thread.MissionID, thread.ID)
	indexKey := s.threadIndexKey(thread.MissionID)
	ridKey := s.threadRidKey(thread.ID)

	// Store thread document
	if err := s.client.JSONSet(ctx, threadKey, "$", thread); err != nil {
		return fmt.Errorf("failed to save thread: %w", err)
	}

	rdb := s.client.Client()

	// Write the reverse index: threadID → missionID (plain string, no JSON).
	// This lets GetThread(threadID) resolve the mission ID without a scan.
	if err := rdb.Set(ctx, ridKey, thread.MissionID.String(), s.config.DefaultTTL).Err(); err != nil {
		return fmt.Errorf("failed to save thread reverse index: %w", err)
	}

	// Add to mission's thread index (score = creation timestamp)
	score := float64(thread.CreatedAt.UnixNano())
	if err := rdb.ZAdd(ctx, indexKey, redis.Z{
		Score:  score,
		Member: thread.ID,
	}).Err(); err != nil {
		return fmt.Errorf("failed to update thread index: %w", err)
	}

	return nil
}

// GetThread retrieves thread metadata by thread ID using the reverse index.
// The reverse index (written by SaveThread) maps threadID → missionID so
// a single Redis GET is all that is needed before fetching the thread document.
func (s *RedisCheckpointStore) GetThread(ctx context.Context, threadID string) (*Thread, error) {
	if threadID == "" {
		return nil, fmt.Errorf("thread ID cannot be empty")
	}

	// Resolve mission ID via the reverse index.
	rdb := s.client.Client()
	missionIDStr, err := rdb.Get(ctx, s.threadRidKey(threadID)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrThreadNotFound
		}
		return nil, fmt.Errorf("failed to read thread reverse index: %w", err)
	}

	missionID, err := types.ParseID(missionIDStr)
	if err != nil {
		return nil, fmt.Errorf("corrupt thread reverse index (mission ID %q): %w", missionIDStr, err)
	}

	return s.GetThreadByMission(ctx, missionID, threadID)
}

// ListThreads returns all threads for a mission, ordered by creation time (newest first).
func (s *RedisCheckpointStore) ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error) {
	if missionID.IsZero() {
		return nil, fmt.Errorf("mission ID cannot be zero")
	}

	indexKey := s.threadIndexKey(missionID)
	rdb := s.client.Client()

	// Get all thread IDs from the sorted set (newest first)
	threadIDs, err := rdb.ZRevRange(ctx, indexKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to query thread index: %w", err)
	}

	if len(threadIDs) == 0 {
		return []*Thread{}, nil
	}

	// Fetch thread documents
	threads := make([]*Thread, 0, len(threadIDs))
	for _, threadID := range threadIDs {
		threadKey := s.threadKey(missionID, threadID)

		var thread Thread
		if err := s.client.JSONGet(ctx, threadKey, "$", &thread); err != nil {
			if state.IsNotFound(err) {
				// Thread was deleted but index wasn't updated - skip it
				continue
			}
			return nil, fmt.Errorf("failed to load thread %s: %w", threadID, err)
		}

		threads = append(threads, &thread)
	}

	return threads, nil
}

// DeleteThread removes thread metadata, the reverse index entry, and removes the thread
// from its mission's sorted-set index. It does NOT delete checkpoints; callers that need
// checkpoint cleanup must call DeleteThreadCheckpoints separately (DefaultThreadManager
// does this via checkpointStore.DeleteThreadCheckpoints before calling this method).
func (s *RedisCheckpointStore) DeleteThread(ctx context.Context, threadID string) error {
	if threadID == "" {
		return fmt.Errorf("thread ID cannot be empty")
	}

	// Look up mission ID via reverse index so we can clean up the sorted-set index.
	thread, err := s.GetThread(ctx, threadID)
	if err != nil {
		if err == ErrThreadNotFound {
			// Already gone; treat as success to make deletion idempotent.
			return nil
		}
		return fmt.Errorf("failed to resolve thread for deletion: %w", err)
	}

	rdb := s.client.Client()
	threadKey := s.threadKey(thread.MissionID, threadID)
	indexKey := s.threadIndexKey(thread.MissionID)
	ridKey := s.threadRidKey(threadID)

	pipe := rdb.Pipeline()
	pipe.Del(ctx, threadKey)
	pipe.Del(ctx, ridKey)
	pipe.ZRem(ctx, indexKey, threadID)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete thread: %w", err)
	}

	return nil
}

// UpdateThread updates an existing thread.
func (s *RedisCheckpointStore) UpdateThread(ctx context.Context, thread *Thread) error {
	// UpdateThread is the same as SaveThread for JSON storage
	return s.SaveThread(ctx, thread)
}

// Additional thread operations with mission ID

// GetThreadByMission retrieves thread metadata by thread ID and mission ID.
func (s *RedisCheckpointStore) GetThreadByMission(ctx context.Context, missionID types.ID, threadID string) (*Thread, error) {
	if threadID == "" {
		return nil, fmt.Errorf("thread ID cannot be empty")
	}
	if missionID.IsZero() {
		return nil, fmt.Errorf("mission ID cannot be zero")
	}

	threadKey := s.threadKey(missionID, threadID)
	var thread Thread
	if err := s.client.JSONGet(ctx, threadKey, "$", &thread); err != nil {
		if state.IsNotFound(err) {
			return nil, ErrThreadNotFound
		}
		return nil, fmt.Errorf("failed to load thread: %w", err)
	}

	return &thread, nil
}

// DeleteThreadByMission removes thread metadata and all its checkpoints.
func (s *RedisCheckpointStore) DeleteThreadByMission(ctx context.Context, missionID types.ID, threadID string) error {
	if threadID == "" {
		return fmt.Errorf("thread ID cannot be empty")
	}
	if missionID.IsZero() {
		return fmt.Errorf("mission ID cannot be zero")
	}

	// First, verify the thread exists
	_, err := s.GetThreadByMission(ctx, missionID, threadID)
	if err != nil {
		return err
	}

	// Delete all checkpoints for the thread
	if err := s.DeleteThreadCheckpoints(ctx, threadID); err != nil {
		return fmt.Errorf("failed to delete thread checkpoints: %w", err)
	}

	// Delete thread metadata and remove from index
	threadKey := s.threadKey(missionID, threadID)
	indexKey := s.threadIndexKey(missionID)

	rdb := s.client.Client()
	pipe := rdb.Pipeline()

	// Delete thread document
	if err := s.client.JSONDel(ctx, threadKey, "$"); err != nil {
		return fmt.Errorf("failed to delete thread: %w", err)
	}

	// Remove from index
	pipe.ZRem(ctx, indexKey, threadID)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update thread index: %w", err)
	}

	return nil
}

// SetTTL updates the TTL for a checkpoint.
func (s *RedisCheckpointStore) SetTTL(ctx context.Context, threadID, checkpointID string, ttl time.Duration) error {
	if threadID == "" {
		return fmt.Errorf("thread ID cannot be empty")
	}
	if checkpointID == "" {
		return fmt.Errorf("checkpoint ID cannot be empty")
	}

	checkpointKey := s.checkpointKey(threadID, checkpointID)
	rdb := s.client.Client()

	// Check if checkpoint exists
	exists, err := rdb.Exists(ctx, checkpointKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check checkpoint existence: %w", err)
	}
	if exists == 0 {
		return ErrCheckpointNotFound
	}

	// Set or remove TTL
	if ttl > 0 {
		if err := rdb.Expire(ctx, checkpointKey, ttl).Err(); err != nil {
			return fmt.Errorf("failed to set TTL: %w", err)
		}
	} else {
		// Remove TTL (persist forever)
		if err := rdb.Persist(ctx, checkpointKey).Err(); err != nil {
			return fmt.Errorf("failed to remove TTL: %w", err)
		}
	}

	return nil
}

// Key building helpers

// threadKey builds the Redis key for thread metadata.
// Format: {prefix}:thread:{mission_id}:{thread_id}
func (s *RedisCheckpointStore) threadKey(missionID types.ID, threadID string) string {
	return fmt.Sprintf("%s:thread:%s:%s", s.config.KeyPrefix, missionID.String(), threadID)
}

// threadIndexKey builds the Redis key for the thread index (sorted set).
// Format: {prefix}:thread:index:{mission_id}
func (s *RedisCheckpointStore) threadIndexKey(missionID types.ID) string {
	return fmt.Sprintf("%s:thread:index:%s", s.config.KeyPrefix, missionID.String())
}

// threadRidKey builds the Redis key for the thread reverse index.
// The reverse index maps a threadID to its missionID so that GetThread can
// resolve the full thread document without requiring the caller to supply the
// mission ID.
// Format: {prefix}:thread:rid:{thread_id}
func (s *RedisCheckpointStore) threadRidKey(threadID string) string {
	return fmt.Sprintf("%s:thread:rid:%s", s.config.KeyPrefix, threadID)
}

// checkpointRidKey builds the Redis key for the checkpoint reverse index.
// The reverse index maps a checkpointID to its threadID so that Load/GetCheckpoint
// can resolve the full document without requiring the caller to supply the thread ID.
// Format: {prefix}:checkpoint:rid:{checkpoint_id}
func (s *RedisCheckpointStore) checkpointRidKey(checkpointID string) string {
	return fmt.Sprintf("%s:checkpoint:rid:%s", s.config.KeyPrefix, checkpointID)
}

// checkpointKey builds the Redis key for checkpoint data.
// Format: {prefix}:checkpoint:{thread_id}:{checkpoint_id}
func (s *RedisCheckpointStore) checkpointKey(threadID, checkpointID string) string {
	return fmt.Sprintf("%s:checkpoint:%s:%s", s.config.KeyPrefix, threadID, checkpointID)
}

// checkpointIndexKey builds the Redis key for the checkpoint index (sorted set).
// Format: {prefix}:checkpoint:index:{thread_id}
func (s *RedisCheckpointStore) checkpointIndexKey(threadID string) string {
	return fmt.Sprintf("%s:checkpoint:index:%s", s.config.KeyPrefix, threadID)
}

// checkpointLatestKey builds the Redis key for the latest checkpoint pointer.
// Format: {prefix}:checkpoint:latest:{thread_id}
func (s *RedisCheckpointStore) checkpointLatestKey(threadID string) string {
	return fmt.Sprintf("%s:checkpoint:latest:%s", s.config.KeyPrefix, threadID)
}

// Ensure RedisCheckpointStore implements CheckpointStore at compile time.
// It also implements ThreadStore from thread_manager.go.
var _ CheckpointStore = (*RedisCheckpointStore)(nil)
