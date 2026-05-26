package checkpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/state"
)

// BlobStore provides an interface for storing and retrieving large objects
// that would be too expensive to store directly in checkpoints.
// This enables efficient checkpoint storage by offloading bulky data (logs,
// binary artifacts, large conversation histories) to separate storage.
//
// Note: This interface replaces the previous BlobStore definition that used
// simple string references. The new version uses thread-scoped blob IDs for
// better lifecycle management and garbage collection.
type BlobStore interface {
	// Store persists a large object and returns a unique blob ID.
	// The blob is associated with a specific thread for lifecycle management.
	Store(ctx context.Context, threadID string, data []byte) (string, error)

	// Get retrieves a blob by its ID within a thread's scope.
	// Returns ErrBlobNotFound if the blob doesn't exist.
	Get(ctx context.Context, threadID string, blobID string) ([]byte, error)

	// Delete removes a specific blob.
	// Returns ErrBlobNotFound if the blob doesn't exist.
	Delete(ctx context.Context, threadID string, blobID string) error

	// DeleteByThread removes all blobs associated with a thread.
	// This is used for garbage collection when a thread is deleted.
	DeleteByThread(ctx context.Context, threadID string) error

	// ShouldStoreAsBlob returns true if data of the given size should be
	// stored as a blob rather than inline in the checkpoint.
	ShouldStoreAsBlob(size int) bool
}

// BlobConfig configures blob storage behavior.
type BlobConfig struct {
	// Threshold is the minimum size in bytes for data to be stored as a blob.
	// Data smaller than this will be stored inline in checkpoints.
	// Default: 1MB (1048576 bytes)
	Threshold int64

	// TTL is the time-to-live for blobs before automatic expiration.
	// Should typically match or exceed checkpoint TTL to prevent data loss.
	// Default: 7 days (168 hours)
	TTL time.Duration

	// KeyPrefix is the Redis key prefix for blob storage.
	// Default: "gibson:checkpoint:blob"
	KeyPrefix string
}

// DefaultBlobConfig returns a BlobConfig with sensible defaults.
func DefaultBlobConfig() BlobConfig {
	return BlobConfig{
		Threshold: 1048576,            // 1MB
		TTL:       7 * 24 * time.Hour, // 7 days
		KeyPrefix: "gibson:checkpoint:blob",
	}
}

// ApplyDefaults fills in missing config values with defaults.
func (c *BlobConfig) ApplyDefaults() {
	defaults := DefaultBlobConfig()
	if c.Threshold <= 0 {
		c.Threshold = defaults.Threshold
	}
	if c.TTL == 0 {
		c.TTL = defaults.TTL
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = defaults.KeyPrefix
	}
}

// RedisBlobStore implements BlobStore using Redis for storage.
// Blobs are stored as raw bytes (not JSON) with automatic TTL expiration.
//
// Redis key pattern: {prefix}:{thread_id}:{blob_id}
// Example: gibson:checkpoint:blob:thread_01HQ7Z:01HQ7ZABCDEF
type RedisBlobStore struct {
	client *state.StateClient
	config BlobConfig
}

// NewRedisBlobStore creates a new Redis-backed blob store.
// The state client should already be connected and healthy.
func NewRedisBlobStore(client *state.StateClient, config BlobConfig) *RedisBlobStore {
	config.ApplyDefaults()
	return &RedisBlobStore{
		client: client,
		config: config,
	}
}

// Store persists a large object to Redis and returns its blob ID.
// Blob IDs are ULIDs for time-ordered, unique identification.
func (s *RedisBlobStore) Store(ctx context.Context, threadID string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("cannot store empty blob data")
	}

	// Generate time-ordered blob ID using ULID
	blobID := ulid.Make().String()

	// Build Redis key
	key := s.buildKey(threadID, blobID)

	// Store blob with TTL
	err := s.client.Client().Set(ctx, key, data, s.config.TTL).Err()
	if err != nil {
		return "", fmt.Errorf("failed to store blob %s: %w", blobID, err)
	}

	return blobID, nil
}

// Get retrieves a blob from Redis by its ID.
func (s *RedisBlobStore) Get(ctx context.Context, threadID string, blobID string) ([]byte, error) {
	if threadID == "" {
		return nil, fmt.Errorf("thread ID cannot be empty")
	}
	if blobID == "" {
		return nil, fmt.Errorf("blob ID cannot be empty")
	}

	key := s.buildKey(threadID, blobID)

	data, err := s.client.Client().Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrBlobNotFound
		}
		return nil, fmt.Errorf("failed to get blob %s: %w", blobID, err)
	}

	return data, nil
}

// Delete removes a specific blob from Redis.
func (s *RedisBlobStore) Delete(ctx context.Context, threadID string, blobID string) error {
	if threadID == "" {
		return fmt.Errorf("thread ID cannot be empty")
	}
	if blobID == "" {
		return fmt.Errorf("blob ID cannot be empty")
	}

	key := s.buildKey(threadID, blobID)

	deleted, err := s.client.Client().Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to delete blob %s: %w", blobID, err)
	}

	if deleted == 0 {
		return ErrBlobNotFound
	}

	return nil
}

// DeleteByThread removes all blobs associated with a thread.
// This uses SCAN to find all matching keys and DEL to remove them.
func (s *RedisBlobStore) DeleteByThread(ctx context.Context, threadID string) error {
	if threadID == "" {
		return fmt.Errorf("thread ID cannot be empty")
	}

	// Pattern to match all blobs for this thread
	pattern := fmt.Sprintf("%s:%s:*", s.config.KeyPrefix, threadID)

	// Use SCAN to iterate through keys (safe for production)
	var cursor uint64
	var deletedCount int64

	for {
		// Scan for keys matching the pattern
		keys, nextCursor, err := s.client.Client().Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan blobs for thread %s: %w", threadID, err)
		}

		// Delete found keys if any
		if len(keys) > 0 {
			deleted, err := s.client.Client().Del(ctx, keys...).Result()
			if err != nil {
				return fmt.Errorf("failed to delete blobs for thread %s: %w", threadID, err)
			}
			deletedCount += deleted
		}

		// Check if scan is complete
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return nil
}

// ShouldStoreAsBlob returns true if data of the given size exceeds the threshold.
func (s *RedisBlobStore) ShouldStoreAsBlob(size int) bool {
	return int64(size) >= s.config.Threshold
}

// buildKey constructs the Redis key for a blob.
func (s *RedisBlobStore) buildKey(threadID, blobID string) string {
	return fmt.Sprintf("%s:%s:%s", s.config.KeyPrefix, threadID, blobID)
}

// BlobReference represents a reference to a blob stored externally.
// This is what gets stored in the checkpoint instead of the actual data.
type BlobReference struct {
	// BlobID is the unique identifier for the blob.
	BlobID string `json:"blob_id"`

	// Size is the original size of the data in bytes.
	Size int64 `json:"size"`

	// CreatedAt is when the blob was created.
	CreatedAt time.Time `json:"created_at"`

	// Type describes the content type (e.g., "memory", "conversation", "custom").
	Type string `json:"type,omitempty"`
}

// ExtractLargeObjects scans an ExecutionState and extracts data that exceeds
// the blob store threshold. Returns:
//   - A modified state with blob references instead of inline data
//   - A map of blob keys to raw data that should be stored
//   - An error if extraction fails
//
// This should be called before serializing a checkpoint for storage.
func ExtractLargeObjects(state *ExecutionState, threshold int64) (*ExecutionState, map[string][]byte, error) {
	// Clone the state to avoid modifying the original
	modifiedState := state.Clone()
	blobs := make(map[string][]byte)

	// Check working memory size
	if len(state.WorkingMemory) > 0 {
		workingMemBytes, err := json.Marshal(state.WorkingMemory)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal working memory: %w", err)
		}

		if int64(len(workingMemBytes)) >= threshold {
			ref := BlobReference{
				BlobID:    ulid.Make().String(),
				Size:      int64(len(workingMemBytes)),
				CreatedAt: time.Now(),
				Type:      "working_memory",
			}

			// Store reference in metadata instead of inline data
			if modifiedState.Metadata == nil {
				modifiedState.Metadata = make(map[string]any)
			}
			modifiedState.Metadata["working_memory_blob"] = ref

			// Clear the inline working memory
			modifiedState.WorkingMemory = make(map[string]any)

			// Add to blobs map
			blobs[ref.BlobID] = workingMemBytes
		}
	}

	// Check mission memory size
	if len(state.MissionMemory) > 0 {
		missionMemBytes, err := json.Marshal(state.MissionMemory)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal mission memory: %w", err)
		}

		if int64(len(missionMemBytes)) >= threshold {
			ref := BlobReference{
				BlobID:    ulid.Make().String(),
				Size:      int64(len(missionMemBytes)),
				CreatedAt: time.Now(),
				Type:      "mission_memory",
			}

			if modifiedState.Metadata == nil {
				modifiedState.Metadata = make(map[string]any)
			}
			modifiedState.Metadata["mission_memory_blob"] = ref

			modifiedState.MissionMemory = make(map[string]any)
			blobs[ref.BlobID] = missionMemBytes
		}
	}

	// Check conversation history size
	if len(state.ConversationHistory) > 0 {
		convBytes, err := SerializeConversation(state.ConversationHistory)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize conversation history: %w", err)
		}

		if int64(len(convBytes)) >= threshold {
			ref := BlobReference{
				BlobID:    ulid.Make().String(),
				Size:      int64(len(convBytes)),
				CreatedAt: time.Now(),
				Type:      "conversation_history",
			}

			if modifiedState.Metadata == nil {
				modifiedState.Metadata = make(map[string]any)
			}
			modifiedState.Metadata["conversation_history_blob"] = ref

			modifiedState.ConversationHistory = []llm.Message{}
			blobs[ref.BlobID] = convBytes
		}
	}

	return modifiedState, blobs, nil
}

// RestoreLargeObjects replaces blob references in an ExecutionState with the
// actual data retrieved from the blob store. This should be called after
// loading a checkpoint from storage.
func RestoreLargeObjects(state *ExecutionState, blobStore BlobStore, threadID string) (*ExecutionState, error) {
	if state.Metadata == nil {
		// No metadata, nothing to restore
		return state, nil
	}

	ctx := context.Background()

	// Restore working memory from blob if referenced
	if refData, ok := state.Metadata["working_memory_blob"]; ok {
		ref, err := parseBlobReference(refData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse working memory blob reference: %w", err)
		}

		data, err := blobStore.Get(ctx, threadID, ref.BlobID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve working memory blob %s: %w", ref.BlobID, err)
		}

		var workingMem map[string]any
		if err := json.Unmarshal(data, &workingMem); err != nil {
			return nil, fmt.Errorf("failed to unmarshal working memory: %w", err)
		}

		state.WorkingMemory = workingMem
		delete(state.Metadata, "working_memory_blob")
	}

	// Restore mission memory from blob if referenced
	if refData, ok := state.Metadata["mission_memory_blob"]; ok {
		ref, err := parseBlobReference(refData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission memory blob reference: %w", err)
		}

		data, err := blobStore.Get(ctx, threadID, ref.BlobID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve mission memory blob %s: %w", ref.BlobID, err)
		}

		var missionMem map[string]any
		if err := json.Unmarshal(data, &missionMem); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mission memory: %w", err)
		}

		state.MissionMemory = missionMem
		delete(state.Metadata, "mission_memory_blob")
	}

	// Restore conversation history from blob if referenced
	if refData, ok := state.Metadata["conversation_history_blob"]; ok {
		ref, err := parseBlobReference(refData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse conversation history blob reference: %w", err)
		}

		data, err := blobStore.Get(ctx, threadID, ref.BlobID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve conversation history blob %s: %w", ref.BlobID, err)
		}

		conversation, err := DeserializeConversation(data)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize conversation history: %w", err)
		}

		state.ConversationHistory = conversation
		delete(state.Metadata, "conversation_history_blob")
	}

	return state, nil
}

// parseBlobReference converts metadata to a BlobReference struct.
func parseBlobReference(refData any) (*BlobReference, error) {
	// Try to handle both direct BlobReference and map[string]any
	switch v := refData.(type) {
	case BlobReference:
		return &v, nil
	case *BlobReference:
		return v, nil
	case map[string]any:
		// Marshal to JSON and unmarshal to BlobReference
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal blob reference: %w", err)
		}
		var ref BlobReference
		if err := json.Unmarshal(data, &ref); err != nil {
			return nil, fmt.Errorf("failed to unmarshal blob reference: %w", err)
		}
		return &ref, nil
	default:
		return nil, fmt.Errorf("invalid blob reference type: %T", refData)
	}
}
