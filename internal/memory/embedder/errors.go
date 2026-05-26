package embedder

import "github.com/zeroroot-ai/gibson/internal/types"

// Embedder error codes
const (
	ErrCodeEmbedderUnavailable  types.ErrorCode = "EMBEDDER_UNAVAILABLE"
	ErrCodeEmbeddingFailed      types.ErrorCode = "EMBEDDING_FAILED"
	ErrCodeEmbeddingBatchFailed types.ErrorCode = "EMBEDDING_BATCH_FAILED"
	ErrCodeInvalidConfig        types.ErrorCode = "INVALID_EMBEDDER_CONFIG"
)
