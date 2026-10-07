// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import "github.com/zeroroot-ai/gibson/internal/infra/types"

// Graph database error codes
const (
	// Connection errors
	ErrCodeGraphConnectionFailed types.ErrorCode = "GRAPH_CONNECTION_FAILED"
	ErrCodeGraphConnectionClosed types.ErrorCode = "GRAPH_CONNECTION_CLOSED"

	// Configuration errors
	ErrCodeGraphInvalidConfig types.ErrorCode = "GRAPH_INVALID_CONFIG"

	// Query errors
	ErrCodeGraphQueryFailed types.ErrorCode = "GRAPH_QUERY_FAILED"
)
