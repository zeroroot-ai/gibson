package checkpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/zero-day-ai/gibson/internal/checkpoint/keyprovider"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ThreadedCheckpointer defines the interface for thread-aware checkpoint management.
// It provides thread creation, checkpoint operations, and state branching capabilities
// for parallel execution path exploration.
type ThreadedCheckpointer interface {
	// Thread management

	// CreateThread creates a new execution thread for the mission.
	// Returns the thread ID on success.
	CreateThread(ctx context.Context, missionID types.ID, opts ...ThreadOption) (string, error)

	// GetThread retrieves a thread by its ID.
	GetThread(ctx context.Context, threadID string) (*Thread, error)

	// ListThreads lists all threads for a mission.
	ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error)

	// Checkpoint operations

	// Checkpoint creates a new checkpoint for the given thread.
	// The state is serialized, compressed, encrypted (if configured), and stored.
	Checkpoint(ctx context.Context, threadID string, state *ExecutionState) (*Checkpoint, error)

	// Restore loads and restores execution state from a checkpoint.
	// The checkpoint is loaded, decrypted, decompressed, and deserialized.
	Restore(ctx context.Context, threadID string, checkpointID string) (*ExecutionState, error)

	// GetLatestCheckpoint retrieves the most recent checkpoint for a thread.
	GetLatestCheckpoint(ctx context.Context, threadID string) (*Checkpoint, error)

	// GetCheckpointHistory retrieves checkpoint history for a thread with filtering.
	GetCheckpointHistory(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error)

	// State modification (creates new branch)

	// UpdateState creates a new checkpoint by modifying an existing checkpoint's state.
	// This creates a new branch point in the execution history.
	UpdateState(ctx context.Context, checkpointID string, updates StateUpdates) (*Checkpoint, error)

	// Cleanup

	// DeleteThread deletes a thread and all its checkpoints.
	DeleteThread(ctx context.Context, threadID string) error

	// ApplyRetentionPolicy applies retention policy to a thread's checkpoints.
	// Old checkpoints beyond the retention period are deleted.
	ApplyRetentionPolicy(ctx context.Context, threadID string) error
}

// HistoryOptions defines options for retrieving checkpoint history.
type HistoryOptions struct {
	// Limit specifies the maximum number of checkpoints to return.
	// 0 means no limit.
	Limit int

	// Offset is the number of checkpoints to skip (for pagination).
	Offset int

	// Ascending determines sort order. If true, oldest first. If false, newest first (default).
	Ascending bool

	// BeforeID is a pagination cursor - return checkpoints created before this ID.
	BeforeID string

	// AfterID is a pagination cursor - return checkpoints created after this ID.
	AfterID string

	// Labels filters checkpoints by labels. Only checkpoints with matching labels are returned.
	Labels []string
}

// StateUpdates defines state modifications to apply to a checkpoint.
// Fields are merged into the existing state to create a new checkpoint.
type StateUpdates struct {
	// WorkingMemory updates to merge into working memory.
	WorkingMemory map[string]any

	// MissionMemory updates to merge into mission memory.
	MissionMemory map[string]any

	// Metadata to add or update on the checkpoint.
	Metadata map[string]string
}


// CheckpointerConfig defines configuration for the threaded checkpointer.
type CheckpointerConfig struct {
	// Serialization options for state serialization
	Serialization SerializeOptions

	// Compression configuration
	Compression CompressionConfig

	// Encryption configuration
	Encryption struct {
		// Enabled determines if encryption is active
		Enabled bool

		// KeyProvider provides encryption keys
		KeyProvider keyprovider.KeyProvider
	}

	// BlobThreshold is the size threshold (in bytes) above which data is stored as a blob
	// instead of inline in the checkpoint. Default: 1MB (1048576 bytes)
	BlobThreshold int64

	// DefaultTTL is the default time-to-live for checkpoints.
	// Checkpoints older than this may be cleaned up by retention policies.
	// 0 means no expiration.
	DefaultTTL time.Duration
}

// DefaultCheckpointerConfig returns a sensible default configuration.
func DefaultCheckpointerConfig() CheckpointerConfig {
	return CheckpointerConfig{
		Serialization: SerializeOptions{
			Format:   FormatMessagePack,
			Compress: true,
			Encrypt:  false,
		},
		Compression:   DefaultCompressionConfig(),
		BlobThreshold: 1048576, // 1MB
		DefaultTTL:    30 * 24 * time.Hour, // 30 days
	}
}

// Note: CheckpointStore interface is defined in store.go
// Note: BlobStore interface is defined in blob_store.go
// Note: ThreadStore interface is defined in thread_manager.go

// DefaultThreadedCheckpointer is the default implementation of ThreadedCheckpointer.
// It orchestrates the full checkpoint pipeline: serialize → compress → encrypt → store.
type DefaultThreadedCheckpointer struct {
	config      CheckpointerConfig
	store       CheckpointStore
	threadStore ThreadStore
	blobStore   BlobStore
	serializer  StateSerializer
	compressor  Compressor
	encryption  EncryptionService
}

// NewThreadedCheckpointer creates a new DefaultThreadedCheckpointer with the provided configuration.
func NewThreadedCheckpointer(
	store CheckpointStore,
	threadStore ThreadStore,
	blobStore BlobStore,
	config CheckpointerConfig,
) *DefaultThreadedCheckpointer {
	// Initialize components
	serializer := NewStateSerializer()
	compressor := NewZstdCompressor(config.Compression)

	var encryptionService EncryptionService
	if config.Encryption.Enabled && config.Encryption.KeyProvider != nil {
		encryptionService = NewAESGCMEncryptionService(config.Encryption.KeyProvider)
	}

	return &DefaultThreadedCheckpointer{
		config:      config,
		store:       store,
		threadStore: threadStore,
		blobStore:   blobStore,
		serializer:  serializer,
		compressor:  compressor,
		encryption:  encryptionService,
	}
}

// CreateThread creates a new execution thread for the mission.
func (d *DefaultThreadedCheckpointer) CreateThread(ctx context.Context, missionID types.ID, opts ...ThreadOption) (string, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context cancelled: %w", err)
	}

	// Create new thread using the existing pattern
	thread := NewThread(missionID)

	// Apply functional options
	for _, opt := range opts {
		opt(thread)
	}
	// Persist thread
	if err := d.threadStore.SaveThread(ctx, thread); err != nil {
		return "", fmt.Errorf("failed to save thread: %w", err)
	}

	return thread.ID, nil
}

// GetThread retrieves a thread by its ID.
func (d *DefaultThreadedCheckpointer) GetThread(ctx context.Context, threadID string) (*Thread, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	thread, err := d.threadStore.GetThread(ctx, threadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get thread: %w", err)
	}

	return thread, nil
}

// ListThreads lists all threads for a mission.
func (d *DefaultThreadedCheckpointer) ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	threads, err := d.threadStore.ListThreads(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list threads: %w", err)
	}

	return threads, nil
}

// Checkpoint creates a new checkpoint for the given thread.
// Pipeline: state → serialize → compress → encrypt → store
func (d *DefaultThreadedCheckpointer) Checkpoint(ctx context.Context, threadID string, state *ExecutionState) (*Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	if state == nil {
		return nil, fmt.Errorf("state cannot be nil")
	}

	// Validate thread exists
	thread, err := d.threadStore.GetThread(ctx, threadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get thread: %w", err)
	}

	// Generate checkpoint ID
	checkpointID := ulid.Make().String()

	// Convert state to checkpoint structure
	checkpoint, err := state.ToCheckpoint(checkpointID, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to convert state to checkpoint: %w", err)
	}

	checkpoint.ThreadID = threadID

	// Set parent ID from thread's last checkpoint
	if thread.LastCheckpointID != "" {
		checkpoint.ParentID = thread.LastCheckpointID
	}

	// Stage 1: Serialize state
	serializedData, err := d.serializeCheckpoint(ctx, checkpoint)
	if err != nil {
		return nil, fmt.Errorf("serialization failed: %w", err)
	}

	// Stage 2: Compress if configured and data exceeds threshold
	var compressedData []byte
	if d.config.Compression.Enabled && d.compressor.ShouldCompress(len(serializedData)) {
		compressedData, err = d.compressor.Compress(serializedData)
		if err != nil {
			return nil, fmt.Errorf("compression failed: %w", err)
		}
		checkpoint.Compressed = true
	} else {
		compressedData = serializedData
		checkpoint.Compressed = false
	}

	// Stage 3: Encrypt if configured
	var finalData []byte
	if d.config.Encryption.Enabled && d.encryption != nil {
		encryptedPayload, err := d.encryption.Encrypt(ctx, compressedData)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}

		// Serialize encrypted payload
		finalData, err = msgpack.Marshal(encryptedPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal encrypted payload: %w", err)
		}

		checkpoint.Encrypted = true
		checkpoint.KeyID = encryptedPayload.KeyID
	} else {
		finalData = compressedData
		checkpoint.Encrypted = false
	}

	// Handle large data by storing as blob
	if int64(len(finalData)) > d.config.BlobThreshold {
		blobID, err := d.blobStore.Store(ctx, threadID, finalData)
		if err != nil {
			return nil, fmt.Errorf("failed to store blob: %w", err)
		}

		if checkpoint.LargeObjectRefs == nil {
			checkpoint.LargeObjectRefs = make(map[string]string)
		}
		checkpoint.LargeObjectRefs["checkpoint_data"] = blobID

		// Clear inline data since it's stored as blob
		checkpoint.WorkingMemory = nil
		checkpoint.MissionMemory = nil
		checkpoint.ConversationHistory = nil
	}

	// Compute checksum
	checksum, err := checkpoint.ComputeChecksum()
	if err != nil {
		return nil, fmt.Errorf("failed to compute checksum: %w", err)
	}
	checkpoint.Checksum = checksum

	// Compute size
	size, err := checkpoint.ComputeSize()
	if err != nil {
		return nil, fmt.Errorf("failed to compute size: %w", err)
	}
	checkpoint.SizeBytes = size

	// Stage 4: Store checkpoint
	if err := d.store.SaveCheckpoint(ctx, checkpoint); err != nil {
		return nil, fmt.Errorf("failed to store checkpoint: %w", err)
	}

	// Update thread metadata
	thread.AddCheckpoint(checkpointID)
	if err := d.threadStore.SaveThread(ctx, thread); err != nil {
		return nil, fmt.Errorf("failed to update thread: %w", err)
	}

	return checkpoint, nil
}

// Restore loads and restores execution state from a checkpoint.
// Pipeline: load → decrypt → decompress → deserialize → state
func (d *DefaultThreadedCheckpointer) Restore(ctx context.Context, threadID string, checkpointID string) (*ExecutionState, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Stage 1: Load checkpoint
	checkpoint, err := d.store.GetCheckpoint(ctx, checkpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to load checkpoint: %w", err)
	}

	// Verify thread ID matches
	if checkpoint.ThreadID != threadID {
		return nil, fmt.Errorf("checkpoint %s does not belong to thread %s", checkpointID, threadID)
	}

	// Verify checksum
	if err := checkpoint.VerifyChecksum(); err != nil {
		return nil, fmt.Errorf("checkpoint integrity check failed: %w", err)
	}

	// Load blob data if stored separately
	var data []byte
	if blobID, ok := checkpoint.LargeObjectRefs["checkpoint_data"]; ok {
		data, err = d.blobStore.Get(ctx, threadID, blobID)
		if err != nil {
			return nil, fmt.Errorf("failed to load blob: %w", err)
		}
	} else {
		// Reconstruct data from inline fields
		data, err = d.serializeCheckpoint(ctx, checkpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize checkpoint: %w", err)
		}
	}

	// Stage 2: Decrypt if encrypted
	if checkpoint.Encrypted {
		if d.encryption == nil {
			return nil, fmt.Errorf("checkpoint is encrypted but no encryption service configured")
		}

		// Deserialize encrypted payload
		var encryptedPayload EncryptedPayload
		if err := msgpack.Unmarshal(data, &encryptedPayload); err != nil {
			return nil, fmt.Errorf("failed to unmarshal encrypted payload: %w", err)
		}

		decryptedData, err := d.encryption.Decrypt(ctx, &encryptedPayload)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
		data = decryptedData
	}

	// Stage 3: Decompress if compressed
	if checkpoint.Compressed {
		decompressedData, err := d.compressor.Decompress(data)
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
		data = decompressedData
	}

	// Stage 4: Deserialize checkpoint
	var restoredCheckpoint Checkpoint
	if err := msgpack.Unmarshal(data, &restoredCheckpoint); err != nil {
		return nil, fmt.Errorf("failed to deserialize checkpoint: %w", err)
	}

	// Stage 5: Convert checkpoint to execution state
	state, err := FromCheckpoint(&restoredCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to convert checkpoint to state: %w", err)
	}

	return state, nil
}

// GetLatestCheckpoint retrieves the most recent checkpoint for a thread.
func (d *DefaultThreadedCheckpointer) GetLatestCheckpoint(ctx context.Context, threadID string) (*Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	checkpoint, err := d.store.GetLatestByThread(ctx, threadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest checkpoint: %w", err)
	}

	return checkpoint, nil
}

// GetCheckpointHistory retrieves checkpoint history for a thread with filtering.
func (d *DefaultThreadedCheckpointer) GetCheckpointHistory(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Pass HistoryOptions directly
	checkpoints, err := d.store.ListByThread(ctx, threadID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list checkpoints: %w", err)
	}

	// Filter by labels if specified
	if len(opts.Labels) > 0 {
		filtered := make([]*Checkpoint, 0, len(checkpoints))
		labelSet := make(map[string]bool)
		for _, label := range opts.Labels {
			labelSet[label] = true
		}

		for _, cp := range checkpoints {
			if cp.Label != "" && labelSet[cp.Label] {
				filtered = append(filtered, cp)
			}
		}
		checkpoints = filtered
	}

	// Apply BeforeID and AfterID filtering
	if opts.BeforeID != "" || opts.AfterID != "" {
		filtered := make([]*Checkpoint, 0, len(checkpoints))
		for _, cp := range checkpoints {
			if opts.BeforeID != "" && cp.ID >= opts.BeforeID {
				continue
			}
			if opts.AfterID != "" && cp.ID <= opts.AfterID {
				continue
			}
			filtered = append(filtered, cp)
		}
		checkpoints = filtered
	}

	return checkpoints, nil
}

// UpdateState creates a new checkpoint by modifying an existing checkpoint's state.
// This creates a new branch point in the execution history.
func (d *DefaultThreadedCheckpointer) UpdateState(ctx context.Context, checkpointID string, updates StateUpdates) (*Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Load the source checkpoint
	sourceCheckpoint, err := d.store.GetCheckpoint(ctx, checkpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to load checkpoint: %w", err)
	}

	// Convert to execution state
	state, err := FromCheckpoint(sourceCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to convert checkpoint to state: %w", err)
	}

	// Apply working memory updates
	if updates.WorkingMemory != nil {
		for k, v := range updates.WorkingMemory {
			state.SetWorkingMemory(k, v)
		}
	}

	// Apply mission memory updates
	if updates.MissionMemory != nil {
		for k, v := range updates.MissionMemory {
			state.SetMissionMemory(k, v)
		}
	}

	// Create new checkpoint with updated state
	newCheckpoint, err := d.Checkpoint(ctx, sourceCheckpoint.ThreadID, state)
	if err != nil {
		return nil, fmt.Errorf("failed to create updated checkpoint: %w", err)
	}

	// Apply metadata updates
	if updates.Metadata != nil {
		if newCheckpoint.Metadata == nil {
			newCheckpoint.Metadata = make(map[string]string)
		}
		for k, v := range updates.Metadata {
			newCheckpoint.Metadata[k] = v
		}
	}

	// Update checkpoint in store
	if err := d.store.SaveCheckpoint(ctx, newCheckpoint); err != nil {
		return nil, fmt.Errorf("failed to save updated checkpoint: %w", err)
	}

	return newCheckpoint, nil
}

// DeleteThread deletes a thread and all its checkpoints.
func (d *DefaultThreadedCheckpointer) DeleteThread(ctx context.Context, threadID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// Delete all blobs for the thread
	if err := d.blobStore.DeleteByThread(ctx, threadID); err != nil {
		return fmt.Errorf("failed to delete thread blobs: %w", err)
	}

	// Delete thread (which should cascade to checkpoints via store implementation)
	if err := d.store.DeleteThread(ctx, threadID); err != nil {
		return fmt.Errorf("failed to delete thread: %w", err)
	}

	return nil
}

// ApplyRetentionPolicy applies retention policy to a thread's checkpoints.
// Checkpoints older than the configured TTL are deleted.
func (d *DefaultThreadedCheckpointer) ApplyRetentionPolicy(ctx context.Context, threadID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	// If no TTL configured, nothing to do
	if d.config.DefaultTTL == 0 {
		return nil
	}

	// Get all checkpoints for thread
	checkpoints, err := d.store.ListByThread(ctx, threadID, HistoryOptions{})
	if err != nil {
		return fmt.Errorf("failed to list checkpoints: %w", err)
	}

	// Calculate cutoff time
	cutoff := time.Now().Add(-d.config.DefaultTTL)

	// Delete expired checkpoints
	for _, checkpoint := range checkpoints {
		if checkpoint.CreatedAt.Before(cutoff) {
			// Delete associated blobs
			if blobID, ok := checkpoint.LargeObjectRefs["checkpoint_data"]; ok {
				if err := d.blobStore.Delete(ctx, threadID, blobID); err != nil {
					// Log error but continue deletion
					// TODO: Add structured logging
				}
			}

			// Delete checkpoint
			if err := d.store.DeleteCheckpoint(ctx, checkpoint.ID); err != nil {
				return fmt.Errorf("failed to delete checkpoint %s: %w", checkpoint.ID, err)
			}
		}
	}

	return nil
}

// serializeCheckpoint serializes a checkpoint to bytes using the configured format.
func (d *DefaultThreadedCheckpointer) serializeCheckpoint(ctx context.Context, checkpoint *Checkpoint) ([]byte, error) {
	switch d.config.Serialization.Format {
	case FormatMessagePack, "":
		data, err := msgpack.Marshal(checkpoint)
		if err != nil {
			return nil, fmt.Errorf("msgpack serialization failed: %w", err)
		}
		return data, nil

	case FormatJSON:
		data, err := json.Marshal(checkpoint)
		if err != nil {
			return nil, fmt.Errorf("json serialization failed: %w", err)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("unsupported serialization format: %s", d.config.Serialization.Format)
	}
}
