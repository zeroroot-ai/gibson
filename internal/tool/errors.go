package tool

import "github.com/zeroroot-ai/gibson/internal/types"

// Tool error codes
const (
	ErrToolNotFound        types.ErrorCode = "TOOL_NOT_FOUND"
	ErrToolAlreadyExists   types.ErrorCode = "TOOL_ALREADY_EXISTS"
	ErrToolExecutionFailed types.ErrorCode = "TOOL_EXECUTION_FAILED"
	ErrToolInvalidInput    types.ErrorCode = "TOOL_INVALID_INPUT"
	ErrToolInvalidOutput   types.ErrorCode = "TOOL_INVALID_OUTPUT"
)
