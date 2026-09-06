// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vector

import "github.com/zeroroot-ai/gibson/internal/infra/types"

// Vector store error codes
const (
	ErrCodeVectorStoreUnavailable types.ErrorCode = "VECTOR_STORE_UNAVAILABLE"
	ErrCodeVectorNotFound         types.ErrorCode = "VECTOR_NOT_FOUND"
	ErrCodeVectorStoreFailed      types.ErrorCode = "VECTOR_STORE_FAILED"
	ErrCodeVectorSearchFailed     types.ErrorCode = "VECTOR_SEARCH_FAILED"
	ErrCodeInvalidConfig          types.ErrorCode = "INVALID_VECTOR_CONFIG"
)
