package memory

import "github.com/zeroroot-ai/gibson/internal/types"

// Memory error codes
const (
	// Working memory errors
	ErrCodeWorkingMemoryFull  types.ErrorCode = "WORKING_MEMORY_FULL"
	ErrCodeTokenLimitExceeded types.ErrorCode = "TOKEN_LIMIT_EXCEEDED"

	// Mission memory errors
	ErrCodeMissionMemoryNotFound types.ErrorCode = "MISSION_MEMORY_NOT_FOUND"
	ErrCodeMissionMemoryStore    types.ErrorCode = "MISSION_MEMORY_STORE_FAILED"
	ErrCodeFTSQueryFailed        types.ErrorCode = "FTS_QUERY_FAILED"

	// Vector store errors
	ErrCodeVectorStoreUnavailable types.ErrorCode = "VECTOR_STORE_UNAVAILABLE"
	ErrCodeVectorNotFound         types.ErrorCode = "VECTOR_NOT_FOUND"
	ErrCodeVectorStoreFailed      types.ErrorCode = "VECTOR_STORE_FAILED"
	ErrCodeVectorSearchFailed     types.ErrorCode = "VECTOR_SEARCH_FAILED"

	// Embedder errors
	ErrCodeEmbedderUnavailable  types.ErrorCode = "EMBEDDER_UNAVAILABLE"
	ErrCodeEmbeddingFailed      types.ErrorCode = "EMBEDDING_FAILED"
	ErrCodeEmbeddingBatchFailed types.ErrorCode = "EMBEDDING_BATCH_FAILED"

	// General errors
	ErrCodeMemoryNotFound      types.ErrorCode = "MEMORY_NOT_FOUND"
	ErrCodeInvalidConfig       types.ErrorCode = "INVALID_MEMORY_CONFIG"
	ErrCodeInvalidMemoryItem   types.ErrorCode = "MEMORY_INVALID_ITEM"
	ErrCodeInvalidVectorRecord types.ErrorCode = "MEMORY_INVALID_VECTOR_RECORD"
	ErrCodeInvalidVectorQuery  types.ErrorCode = "MEMORY_INVALID_VECTOR_QUERY"
)

// NewWorkingMemoryFullError creates an error for when working memory is full
func NewWorkingMemoryFullError(message string) *types.GibsonError {
	return types.NewError(ErrCodeWorkingMemoryFull, message)
}

// NewTokenLimitExceededError creates an error for when token limit is exceeded
func NewTokenLimitExceededError(message string) *types.GibsonError {
	return types.NewError(ErrCodeTokenLimitExceeded, message)
}

// NewMissionMemoryNotFoundError creates an error for when mission memory item is not found
func NewMissionMemoryNotFoundError(key string) *types.GibsonError {
	return types.NewError(ErrCodeMissionMemoryNotFound, "mission memory item not found: "+key)
}

// NewMissionMemoryStoreError creates an error for when mission memory store operation fails
func NewMissionMemoryStoreError(message string, cause error) *types.GibsonError {
	return types.WrapError(ErrCodeMissionMemoryStore, message, cause)
}

// NewFTSQueryError creates an error for when FTS query fails
func NewFTSQueryError(message string, cause error) *types.GibsonError {
	return types.WrapError(ErrCodeFTSQueryFailed, message, cause)
}

// NewVectorStoreUnavailableError creates an error for when vector store is unavailable
func NewVectorStoreUnavailableError(message string) *types.GibsonError {
	return types.NewError(ErrCodeVectorStoreUnavailable, message)
}

// NewVectorNotFoundError creates an error for when vector is not found
func NewVectorNotFoundError(id string) *types.GibsonError {
	return types.NewError(ErrCodeVectorNotFound, "vector not found: "+id)
}

// NewVectorStoreError creates an error for when vector store operation fails
func NewVectorStoreError(message string, cause error) *types.GibsonError {
	return types.WrapError(ErrCodeVectorStoreFailed, message, cause)
}

// NewVectorSearchError creates an error for when vector search fails
func NewVectorSearchError(message string, cause error) *types.GibsonError {
	return types.WrapError(ErrCodeVectorSearchFailed, message, cause)
}

// NewEmbedderUnavailableError creates an error for when embedder is unavailable
func NewEmbedderUnavailableError(message string) *types.GibsonError {
	return types.NewError(ErrCodeEmbedderUnavailable, message)
}

// NewEmbeddingError creates an error for when embedding generation fails
func NewEmbeddingError(message string, cause error) *types.GibsonError {
	return types.WrapError(ErrCodeEmbeddingFailed, message, cause)
}

// NewEmbeddingBatchError creates an error for when batch embedding fails
func NewEmbeddingBatchError(message string, cause error) *types.GibsonError {
	return types.WrapError(ErrCodeEmbeddingBatchFailed, message, cause)
}

// NewMemoryNotFoundError creates a generic memory not found error
func NewMemoryNotFoundError(key string) *types.GibsonError {
	return types.NewError(ErrCodeMemoryNotFound, "memory item not found: "+key)
}

// NewInvalidConfigError creates an error for invalid memory configuration
func NewInvalidConfigError(message string) *types.GibsonError {
	return types.NewError(ErrCodeInvalidConfig, message)
}

// NewInvalidMemoryItemError creates an error for invalid memory items
func NewInvalidMemoryItemError(message string) *types.GibsonError {
	return types.NewError(ErrCodeInvalidMemoryItem, message)
}

// NewInvalidVectorRecordError creates an error for invalid vector records
func NewInvalidVectorRecordError(message string) *types.GibsonError {
	return types.NewError(ErrCodeInvalidVectorRecord, message)
}

// NewInvalidVectorQueryError creates an error for invalid vector queries
func NewInvalidVectorQueryError(message string) *types.GibsonError {
	return types.NewError(ErrCodeInvalidVectorQuery, message)
}
