package vector

import "github.com/zeroroot-ai/gibson/internal/types"

// Vector store error codes
const (
	ErrCodeVectorStoreUnavailable types.ErrorCode = "VECTOR_STORE_UNAVAILABLE"
	ErrCodeVectorNotFound         types.ErrorCode = "VECTOR_NOT_FOUND"
	ErrCodeVectorStoreFailed      types.ErrorCode = "VECTOR_STORE_FAILED"
	ErrCodeVectorSearchFailed     types.ErrorCode = "VECTOR_SEARCH_FAILED"
	ErrCodeInvalidConfig          types.ErrorCode = "INVALID_VECTOR_CONFIG"
)
