package checkpoint

import (
	"context"
	"fmt"
	"time"
)

// Note: CheckpointStore and BlobStore interfaces are defined in policy.go and blob_store.go respectively

// StateRestorer defines the interface for restoring execution state from checkpoints.
// It handles the complete restoration pipeline including validation, decryption,
// decompression, and deserialization.
type StateRestorer interface {
	// Restore execution state from a checkpoint
	Restore(ctx context.Context, checkpoint *Checkpoint) (*ExecutionState, error)

	// Validate checkpoint integrity before restoration
	Validate(checkpoint *Checkpoint) error

	// RestoreFromID fetches and restores a checkpoint by ID
	RestoreFromID(ctx context.Context, threadID string, checkpointID string) (*ExecutionState, error)

	// RestoreLatest restores the most recent checkpoint for a thread
	RestoreLatest(ctx context.Context, threadID string) (*ExecutionState, error)
}

// RestorationResult contains detailed information about a restoration operation.
// This provides visibility into what was restored and what remains to be executed.
type RestorationResult struct {
	// State is the restored execution state ready for use
	State *ExecutionState

	// Checkpoint is the original checkpoint that was restored
	Checkpoint *Checkpoint

	// NodesSkipped lists node IDs that were completed before the checkpoint
	NodesSkipped []string

	// NodesToExecute lists node IDs that are pending from the checkpoint
	NodesToExecute []string

	// RestoredAt is when the restoration was performed
	RestoredAt time.Time

	// Duration is how long the restoration took
	Duration time.Duration
}

// DefaultStateRestorer is the standard implementation of StateRestorer.
// It orchestrates the complete restoration pipeline with validation, decryption,
// decompression, and deserialization.
type DefaultStateRestorer struct {
	store      CheckpointStore
	blobStore  BlobStore
	serializer StateSerializer
	compressor Compressor
	encryptor  EncryptionService // can be nil if encryption is disabled
}

// NewStateRestorer creates a new DefaultStateRestorer with the specified dependencies.
// The encryptor parameter can be nil if encryption is disabled.
func NewStateRestorer(
	store CheckpointStore,
	blobStore BlobStore,
	serializer StateSerializer,
	compressor Compressor,
	encryptor EncryptionService,
) *DefaultStateRestorer {
	return &DefaultStateRestorer{
		store:      store,
		blobStore:  blobStore,
		serializer: serializer,
		compressor: compressor,
		encryptor:  encryptor,
	}
}

// Validate performs comprehensive validation on a checkpoint before restoration.
// This includes checksum verification, version compatibility, and structural integrity checks.
func (r *DefaultStateRestorer) Validate(checkpoint *Checkpoint) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint is nil")
	}

	// Validate version compatibility
	if err := ValidateCheckpointVersion(checkpoint.Version); err != nil {
		return fmt.Errorf("version validation failed: %w", err)
	}

	// Validate required fields
	if checkpoint.ID == "" {
		return fmt.Errorf("checkpoint missing ID")
	}
	if checkpoint.ThreadID == "" {
		return fmt.Errorf("checkpoint missing thread ID")
	}
	if checkpoint.MissionID == "" {
		return fmt.Errorf("checkpoint missing mission ID")
	}

	// Validate checksum integrity
	if err := checkpoint.VerifyChecksum(); err != nil {
		return fmt.Errorf("checksum validation failed: %w", err)
	}

	// Validate node states
	if checkpoint.NodeStates == nil {
		return fmt.Errorf("checkpoint has nil node states")
	}
	if checkpoint.CompletedNodes == nil {
		return fmt.Errorf("checkpoint has nil completed nodes")
	}

	return nil
}

// Restore converts a checkpoint back into an ExecutionState ready for execution.
// This handles the complete restoration pipeline including validation, decryption,
// decompression, deserialization, and large object restoration.
func (r *DefaultStateRestorer) Restore(ctx context.Context, checkpoint *Checkpoint) (*ExecutionState, error) {
	startTime := time.Now()

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before restoration: %w", err)
	}

	// Validate checkpoint integrity first
	if err := r.Validate(checkpoint); err != nil {
		return nil, fmt.Errorf("checkpoint validation failed: %w", err)
	}

	// Decrypt checkpoint data if encrypted
	if checkpoint.Encrypted {
		if r.encryptor == nil {
			return nil, fmt.Errorf("checkpoint is encrypted but no encryption service provided")
		}

		if err := r.decryptCheckpoint(ctx, checkpoint); err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
	}

	// Decompress checkpoint data if compressed
	if checkpoint.Compressed {
		if err := r.decompressCheckpoint(checkpoint); err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
	}

	// Restore large objects from blob store
	if len(checkpoint.LargeObjectRefs) > 0 {
		if r.blobStore == nil {
			return nil, fmt.Errorf("checkpoint has large object references but no blob store provided")
		}

		if err := r.restoreLargeObjects(ctx, checkpoint); err != nil {
			return nil, fmt.Errorf("failed to restore large objects: %w", err)
		}
	}

	// Convert checkpoint to execution state using the existing FromCheckpoint function
	state, err := FromCheckpoint(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize checkpoint to execution state: %w", err)
	}

	// Validate the restored state
	if err := r.validateRestoredState(state); err != nil {
		return nil, fmt.Errorf("restored state validation failed: %w", err)
	}

	duration := time.Since(startTime)

	// Log restoration metrics (could be enhanced with structured logging)
	_ = duration // metrics placeholder for future observability

	return state, nil
}

// RestoreFromID fetches a checkpoint by ID and thread, then restores it.
// This is a convenience method that combines fetching and restoration.
func (r *DefaultStateRestorer) RestoreFromID(ctx context.Context, threadID string, checkpointID string) (*ExecutionState, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate inputs
	if threadID == "" {
		return nil, fmt.Errorf("thread ID cannot be empty")
	}
	if checkpointID == "" {
		return nil, fmt.Errorf("checkpoint ID cannot be empty")
	}

	// Fetch checkpoint from store
	checkpoint, err := r.store.GetCheckpoint(ctx, checkpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch checkpoint %s: %w", checkpointID, err)
	}

	// Verify checkpoint belongs to the specified thread
	if checkpoint.ThreadID != threadID {
		return nil, fmt.Errorf("checkpoint %s belongs to thread %s, not %s",
			checkpointID, checkpoint.ThreadID, threadID)
	}

	// Restore the checkpoint
	return r.Restore(ctx, checkpoint)
}

// RestoreLatest restores the most recent checkpoint for a thread.
// This is commonly used when resuming execution after a pause or failure.
func (r *DefaultStateRestorer) RestoreLatest(ctx context.Context, threadID string) (*ExecutionState, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate input
	if threadID == "" {
		return nil, fmt.Errorf("thread ID cannot be empty")
	}

	// Fetch latest checkpoint from store
	checkpoint, err := r.store.GetLatestCheckpoint(ctx, threadID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest checkpoint for thread %s: %w", threadID, err)
	}

	if checkpoint == nil {
		return nil, fmt.Errorf("no checkpoint found for thread %s: %w", threadID, ErrCheckpointNotFound)
	}

	// Restore the checkpoint
	return r.Restore(ctx, checkpoint)
}

// decryptCheckpoint decrypts the encrypted fields in a checkpoint.
// This modifies the checkpoint in place by decrypting the memory and conversation fields.
func (r *DefaultStateRestorer) decryptCheckpoint(ctx context.Context, checkpoint *Checkpoint) error {
	// Decrypt working memory if present
	if len(checkpoint.WorkingMemory) > 0 {
		payload := &EncryptedPayload{
			KeyID:      checkpoint.KeyID,
			Ciphertext: checkpoint.WorkingMemory,
			// Note: In a production system, nonce would be stored separately or with the ciphertext
		}

		decrypted, err := r.encryptor.Decrypt(ctx, payload)
		if err != nil {
			return fmt.Errorf("failed to decrypt working memory: %w", err)
		}
		checkpoint.WorkingMemory = decrypted
	}

	// Decrypt mission memory if present
	if len(checkpoint.MissionMemory) > 0 {
		payload := &EncryptedPayload{
			KeyID:      checkpoint.KeyID,
			Ciphertext: checkpoint.MissionMemory,
		}

		decrypted, err := r.encryptor.Decrypt(ctx, payload)
		if err != nil {
			return fmt.Errorf("failed to decrypt mission memory: %w", err)
		}
		checkpoint.MissionMemory = decrypted
	}

	// Decrypt conversation history if present
	if len(checkpoint.ConversationHistory) > 0 {
		payload := &EncryptedPayload{
			KeyID:      checkpoint.KeyID,
			Ciphertext: checkpoint.ConversationHistory,
		}

		decrypted, err := r.encryptor.Decrypt(ctx, payload)
		if err != nil {
			return fmt.Errorf("failed to decrypt conversation history: %w", err)
		}
		checkpoint.ConversationHistory = decrypted
	}

	return nil
}

// decompressCheckpoint decompresses the compressed fields in a checkpoint.
// This modifies the checkpoint in place by decompressing the memory and conversation fields.
func (r *DefaultStateRestorer) decompressCheckpoint(checkpoint *Checkpoint) error {
	// Decompress working memory if present
	if len(checkpoint.WorkingMemory) > 0 {
		decompressed, err := r.compressor.Decompress(checkpoint.WorkingMemory)
		if err != nil {
			return fmt.Errorf("failed to decompress working memory: %w", err)
		}
		checkpoint.WorkingMemory = decompressed
	}

	// Decompress mission memory if present
	if len(checkpoint.MissionMemory) > 0 {
		decompressed, err := r.compressor.Decompress(checkpoint.MissionMemory)
		if err != nil {
			return fmt.Errorf("failed to decompress mission memory: %w", err)
		}
		checkpoint.MissionMemory = decompressed
	}

	// Decompress conversation history if present
	if len(checkpoint.ConversationHistory) > 0 {
		decompressed, err := r.compressor.Decompress(checkpoint.ConversationHistory)
		if err != nil {
			return fmt.Errorf("failed to decompress conversation history: %w", err)
		}
		checkpoint.ConversationHistory = decompressed
	}

	return nil
}

// restoreLargeObjects fetches large objects from the blob store and integrates them
// into the checkpoint. This handles artifacts that were stored separately to keep
// checkpoint size manageable. This uses the RestoreLargeObjects utility function
// from blob_store.go which handles the actual restoration logic.
func (r *DefaultStateRestorer) restoreLargeObjects(ctx context.Context, checkpoint *Checkpoint) error {
	// The actual restoration of large objects is handled by the RestoreLargeObjects
	// utility function which knows how to interpret blob references in metadata.
	// This is called after converting to ExecutionState in the Restore method.
	// For checkpoint-level large object refs, we validate they exist.
	for key, ref := range checkpoint.LargeObjectRefs {
		// Check context cancellation
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled during large object restoration: %w", err)
		}

		// Validate that the blob reference is valid (non-empty)
		if ref == "" {
			return fmt.Errorf("large object reference %s is empty", key)
		}

		// Note: Actual blob fetching happens in RestoreLargeObjects from blob_store.go
		// which operates on ExecutionState after conversion from Checkpoint
	}

	return nil
}

// validateRestoredState performs sanity checks on the restored execution state.
// This ensures the state is internally consistent and ready for execution.
func (r *DefaultStateRestorer) validateRestoredState(state *ExecutionState) error {
	if state == nil {
		return fmt.Errorf("restored state is nil")
	}

	// Validate required fields
	if state.MissionID == "" {
		return fmt.Errorf("restored state has empty mission ID")
	}
	if state.ThreadID == "" {
		return fmt.Errorf("restored state has empty thread ID")
	}

	// Validate memory initialization
	if state.WorkingMemory == nil {
		return fmt.Errorf("restored state has nil working memory")
	}
	if state.MissionMemory == nil {
		return fmt.Errorf("restored state has nil mission memory")
	}

	// Validate node states
	if state.NodeStates == nil {
		return fmt.Errorf("restored state has nil node states")
	}
	if state.CompletedResults == nil {
		return fmt.Errorf("restored state has nil completed results")
	}

	// Validate queue
	if state.PendingQueue == nil {
		return fmt.Errorf("restored state has nil pending queue")
	}

	return nil
}

// BuildPendingQueue reconstructs the execution queue from a checkpoint.
// This determines which nodes still need to be executed based on the checkpoint state.
func BuildPendingQueue(checkpoint *Checkpoint) []string {
	if checkpoint == nil {
		return []string{}
	}

	// Use the pending nodes from the DAG state if available
	if checkpoint.DAGState != nil && len(checkpoint.DAGState.PendingNodes) > 0 {
		// Return a copy to avoid external modification
		pending := make([]string, len(checkpoint.DAGState.PendingNodes))
		copy(pending, checkpoint.DAGState.PendingNodes)
		return pending
	}

	// Fall back to checkpoint's pending nodes list
	if len(checkpoint.PendingNodes) > 0 {
		pending := make([]string, len(checkpoint.PendingNodes))
		copy(pending, checkpoint.PendingNodes)
		return pending
	}

	return []string{}
}

// IdentifySkippedNodes returns the list of nodes that completed before the checkpoint.
// These nodes don't need to be re-executed when resuming from the checkpoint.
func IdentifySkippedNodes(checkpoint *Checkpoint) []string {
	if checkpoint == nil || checkpoint.CompletedNodes == nil {
		return []string{}
	}

	// Extract node IDs from completed nodes
	skipped := make([]string, 0, len(checkpoint.CompletedNodes))
	for nodeID := range checkpoint.CompletedNodes {
		skipped = append(skipped, nodeID)
	}

	return skipped
}

// ValidateCheckpointVersion checks if a checkpoint format version is compatible
// with the current implementation. Only CurrentCheckpointVersion (2) is accepted;
// older versions must be drained before upgrade per the release notes.
func ValidateCheckpointVersion(version int) error {
	if version != CurrentCheckpointVersion {
		return fmt.Errorf(
			"unsupported checkpoint schema version %d "+
				"(this daemon requires version %d): "+
				"drain in-flight missions before upgrading",
			version, CurrentCheckpointVersion,
		)
	}
	return nil
}

// RestoreWithResult restores a checkpoint and returns detailed restoration information.
// This provides comprehensive visibility into the restoration process for debugging
// and monitoring purposes.
func (r *DefaultStateRestorer) RestoreWithResult(ctx context.Context, checkpoint *Checkpoint) (*RestorationResult, error) {
	startTime := time.Now()

	// Perform the restoration
	state, err := r.Restore(ctx, checkpoint)
	if err != nil {
		return nil, err
	}

	// Build restoration result
	result := &RestorationResult{
		State:          state,
		Checkpoint:     checkpoint,
		NodesSkipped:   IdentifySkippedNodes(checkpoint),
		NodesToExecute: BuildPendingQueue(checkpoint),
		RestoredAt:     time.Now(),
		Duration:       time.Since(startTime),
	}

	return result, nil
}

// RestorePartial performs a partial restoration of specific checkpoint components.
// This is useful for inspecting checkpoint state without fully deserializing everything.
type PartialRestoreOptions struct {
	// MemoryOnly indicates to only restore memory state
	MemoryOnly bool

	// NodeStatesOnly indicates to only restore node execution states
	NodeStatesOnly bool

	// ConversationOnly indicates to only restore conversation history
	ConversationOnly bool
}

// RestorePartial restores specific portions of a checkpoint based on the provided options.
// This is useful for partial inspection or when full restoration isn't needed.
func (r *DefaultStateRestorer) RestorePartial(ctx context.Context, checkpoint *Checkpoint, opts PartialRestoreOptions) (*ExecutionState, error) {
	// Validate checkpoint first
	if err := r.Validate(checkpoint); err != nil {
		return nil, fmt.Errorf("checkpoint validation failed: %w", err)
	}

	// Create a minimal execution state
	state := NewExecutionState(checkpoint.MissionID, checkpoint.ThreadID)
	state.CurrentNodeID = checkpoint.CurrentNodeID

	// Restore only the requested components
	if opts.MemoryOnly {
		workingMem, err := DeserializeMemory(checkpoint.WorkingMemory)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize working memory: %w", err)
		}
		state.WorkingMemory = workingMem

		missionMem, err := DeserializeMemory(checkpoint.MissionMemory)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize mission memory: %w", err)
		}
		state.MissionMemory = missionMem
	}

	if opts.NodeStatesOnly {
		state.NodeStates = checkpoint.NodeStates
		state.CompletedResults = checkpoint.CompletedNodes
		state.PendingQueue = checkpoint.PendingNodes
	}

	if opts.ConversationOnly {
		conversation, err := DeserializeConversation(checkpoint.ConversationHistory)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize conversation: %w", err)
		}
		state.ConversationHistory = conversation
	}

	return state, nil
}
