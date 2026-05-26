package graph

import "github.com/zeroroot-ai/gibson/internal/types"

// Graph database error codes
const (
	// Connection errors
	ErrCodeGraphConnectionFailed types.ErrorCode = "GRAPH_CONNECTION_FAILED"
	ErrCodeGraphConnectionLost   types.ErrorCode = "GRAPH_CONNECTION_LOST"
	ErrCodeGraphConnectionClosed types.ErrorCode = "GRAPH_CONNECTION_CLOSED"

	// Configuration errors
	ErrCodeGraphInvalidConfig types.ErrorCode = "GRAPH_INVALID_CONFIG"

	// Query errors
	ErrCodeGraphQueryFailed   types.ErrorCode = "GRAPH_QUERY_FAILED"
	ErrCodeGraphQueryTimeout  types.ErrorCode = "GRAPH_QUERY_TIMEOUT"
	ErrCodeGraphInvalidQuery  types.ErrorCode = "GRAPH_INVALID_QUERY"
	ErrCodeGraphResultParsing types.ErrorCode = "GRAPH_RESULT_PARSING"

	// Node errors
	ErrCodeGraphNodeNotFound     types.ErrorCode = "GRAPH_NODE_NOT_FOUND"
	ErrCodeGraphNodeCreateFailed types.ErrorCode = "GRAPH_NODE_CREATE_FAILED"
	ErrCodeGraphNodeDeleteFailed types.ErrorCode = "GRAPH_NODE_DELETE_FAILED"

	// Relationship errors
	ErrCodeGraphRelationshipCreateFailed types.ErrorCode = "GRAPH_RELATIONSHIP_CREATE_FAILED"
	ErrCodeGraphRelationshipDeleteFailed types.ErrorCode = "GRAPH_RELATIONSHIP_DELETE_FAILED"
)
