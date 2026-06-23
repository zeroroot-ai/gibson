package harness

import (
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Harness error codes for agent harness operations.
// These errors are returned when agents interact with the harness
// for tool execution, plugin queries, and agent delegation.
const (
	// ErrHarnessSlotNotFound indicates a requested LLM slot does not exist or is not configured
	ErrHarnessSlotNotFound types.ErrorCode = "HARNESS_SLOT_NOT_FOUND"

	// ErrHarnessToolNotFound indicates the requested tool is not registered or available
	ErrHarnessToolNotFound types.ErrorCode = "HARNESS_TOOL_NOT_FOUND"

	// ErrHarnessPluginNotFound indicates the requested plugin is not registered or available
	ErrHarnessPluginNotFound types.ErrorCode = "HARNESS_PLUGIN_NOT_FOUND"

	// ErrHarnessPluginMethodNotFound indicates the plugin exists but doesn't support the requested method
	ErrHarnessPluginMethodNotFound types.ErrorCode = "HARNESS_PLUGIN_METHOD_NOT_FOUND"

	// ErrHarnessAgentNotFound indicates the requested agent for delegation is not registered
	ErrHarnessAgentNotFound types.ErrorCode = "HARNESS_AGENT_NOT_FOUND"

	// ErrHarnessCompletionFailed indicates LLM completion request failed
	ErrHarnessCompletionFailed types.ErrorCode = "HARNESS_COMPLETION_FAILED"

	// ErrHarnessToolExecutionFailed indicates tool execution failed during harness operation
	ErrHarnessToolExecutionFailed types.ErrorCode = "HARNESS_TOOL_EXECUTION_FAILED"

	// ErrHarnessDelegationFailed indicates agent delegation failed
	ErrHarnessDelegationFailed types.ErrorCode = "HARNESS_DELEGATION_FAILED"

	// ErrHarnessInvalidConfig indicates the harness configuration is invalid or incomplete
	ErrHarnessInvalidConfig types.ErrorCode = "HARNESS_INVALID_CONFIG"

	// ErrChildMissionLimitExceeded indicates the parent mission has reached its maximum child count
	ErrChildMissionLimitExceeded types.ErrorCode = "HARNESS_CHILD_MISSION_LIMIT_EXCEEDED"

	// ErrMissionDepthLimitExceeded indicates the mission depth limit has been reached
	ErrMissionDepthLimitExceeded types.ErrorCode = "HARNESS_MISSION_DEPTH_LIMIT_EXCEEDED"

	// ErrConcurrentMissionLimitExceeded indicates the system-wide concurrent mission limit has been reached
	ErrConcurrentMissionLimitExceeded types.ErrorCode = "HARNESS_CONCURRENT_MISSION_LIMIT_EXCEEDED"
)
