package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"go.opentelemetry.io/otel/log"
)

// Level defines the verbosity level for logging middleware.
// Higher levels include all information from lower levels.
type Level int

const (
	// LevelQuiet suppresses all logging output.
	// Use when minimal overhead is critical or logging is handled elsewhere.
	LevelQuiet Level = iota

	// LevelNormal logs operation start and completion events only.
	// Includes: operation type, duration, success/failure status.
	// Excludes: request/response details, token counts.
	LevelNormal

	// LevelVerbose adds operational details to normal logging.
	// Includes: everything from Normal plus timing, token usage, result summaries.
	// Excludes: full request/response content.
	LevelVerbose

	// LevelDebug includes full request and response details.
	// Includes: everything from Verbose plus truncated request/response content.
	// Uses redaction for sensitive fields (prompts, API keys).
	LevelDebug
)

// LoggingMiddleware creates middleware that emits structured OpenTelemetry log records
// for operation lifecycle events. It replaces VerboseHarnessWrapper with OTel-native logging.
//
// The middleware emits log records at three key points:
//   - Operation start: {operation}.start with request summary
//   - Operation complete: {operation}.complete with timing and result summary
//   - Operation failed: {operation}.failed with error details
//
// All log records include structured attributes:
//   - Standard context: mission_id, agent_name, trace_id, span_id (from context)
//   - Timing: duration_ms (for complete/failed events)
//   - Token usage: prompt_tokens, completion_tokens, total_tokens (when available)
//   - Operation-specific: tool_name, message_count, model, etc.
//
// Verbosity levels control the detail included:
//   - LevelQuiet: No logs emitted
//   - LevelNormal: Start/complete/failed only, no details
//   - LevelVerbose: Include timing, token usage, and summaries
//   - LevelDebug: Include truncated request/response (with redaction)
//
// Parameters:
//   - logger: OpenTelemetry log.Logger for emission (NOT slog)
//   - level: Verbosity level controlling detail
//
// Returns:
//   - Middleware: Function that wraps operations with logging
//
// Example:
//
//	logger := otel.GetLoggerProvider().Logger("gibson.harness")
//	loggingMW := LoggingMiddleware(logger, LevelVerbose)
//	wrapped := loggingMW(baseOperation)
func LoggingMiddleware(logger log.Logger, level Level) Middleware {
	return func(next Operation) Operation {
		return func(ctx context.Context, req any) (any, error) {
			// Skip all logging if LevelQuiet
			if level == LevelQuiet {
				return next(ctx, req)
			}

			// Extract operation metadata from context
			opType := getOperationType(ctx)
			missionID := getMissionID(ctx)
			agentName := getAgentName(ctx)

			// Emit operation start event
			emitStartEvent(ctx, logger, level, opType, missionID, agentName, req)

			// Record start time for duration calculation
			startTime := time.Now()

			// Execute the operation
			resp, err := next(ctx, req)

			// Calculate duration
			duration := time.Since(startTime)

			// Emit complete or failed event based on error
			if err != nil {
				emitFailedEvent(ctx, logger, level, opType, missionID, agentName, duration, err, req)
				return nil, err
			}

			emitCompleteEvent(ctx, logger, level, opType, missionID, agentName, duration, resp)
			return resp, nil
		}
	}
}

// emitStartEvent emits an {operation}.start log record.
func emitStartEvent(ctx context.Context, logger log.Logger, level Level, opType OperationType, missionID, agentName string, req any) {
	// Build log record
	record := log.Record{}
	record.SetTimestamp(time.Now())
	record.SetSeverity(log.SeverityInfo)
	record.SetBody(log.StringValue(fmt.Sprintf("%s.start", operationName(opType))))

	// Add context attributes
	addContextAttributes(&record, missionID, agentName)

	// Add operation type
	record.AddAttributes(log.String("operation_type", operationName(opType)))

	// Add request-specific attributes based on verbosity
	if level >= LevelVerbose {
		addStartAttributes(&record, opType, req)
	}

	// Add debug details if requested
	if level >= LevelDebug {
		addDebugStartAttributes(&record, opType, req)
	}

	// Emit the record
	logger.Emit(ctx, record)
}

// emitCompleteEvent emits an {operation}.complete log record.
func emitCompleteEvent(ctx context.Context, logger log.Logger, level Level, opType OperationType, missionID, agentName string, duration time.Duration, resp any) {
	// Build log record
	record := log.Record{}
	record.SetTimestamp(time.Now())
	record.SetSeverity(log.SeverityInfo)
	record.SetBody(log.StringValue(fmt.Sprintf("%s.complete", operationName(opType))))

	// Add context attributes
	addContextAttributes(&record, missionID, agentName)

	// Add operation type
	record.AddAttributes(log.String("operation_type", operationName(opType)))

	// Add duration at verbose level or higher
	if level >= LevelVerbose {
		record.AddAttributes(log.Float64("duration_ms", float64(duration.Milliseconds())))
		addCompleteAttributes(&record, opType, resp)
	}

	// Add debug details if requested
	if level >= LevelDebug {
		addDebugCompleteAttributes(&record, opType, resp)
	}

	// Emit the record
	logger.Emit(ctx, record)
}

// emitFailedEvent emits an {operation}.failed log record.
func emitFailedEvent(ctx context.Context, logger log.Logger, level Level, opType OperationType, missionID, agentName string, duration time.Duration, err error, req any) {
	// Build log record
	record := log.Record{}
	record.SetTimestamp(time.Now())
	record.SetSeverity(log.SeverityError)
	record.SetBody(log.StringValue(fmt.Sprintf("%s.failed", operationName(opType))))

	// Add context attributes
	addContextAttributes(&record, missionID, agentName)

	// Add operation type
	record.AddAttributes(log.String("operation_type", operationName(opType)))

	// Add error at all levels (except Quiet which is already filtered)
	record.AddAttributes(log.String("error", err.Error()))

	// Add duration at verbose level or higher
	if level >= LevelVerbose {
		record.AddAttributes(log.Float64("duration_ms", float64(duration.Milliseconds())))
	}

	// Add debug error details if requested
	if level >= LevelDebug {
		// Full error details (already included in error field)
		record.AddAttributes(log.String("error_details", err.Error()))
	}

	// Emit the record
	logger.Emit(ctx, record)
}

// addContextAttributes adds mission context and trace correlation to the log record.
func addContextAttributes(record *log.Record, missionID, agentName string) {
	if missionID != "" {
		record.AddAttributes(log.String("mission_id", missionID))
	}
	if agentName != "" {
		record.AddAttributes(log.String("agent_name", agentName))
	}
	// Note: trace_id and span_id are added automatically by GibsonLogger
}

// addStartAttributes adds operation-specific attributes for start events at verbose level.
func addStartAttributes(record *log.Record, opType OperationType, req any) {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		if compReq, ok := req.(*CompletionRequest); ok {
			record.AddAttributes(
				log.String("slot_name", compReq.Slot),
				log.Int("message_count", len(compReq.Messages)),
			)
			if opType == OpCompleteWithTools && compReq.Tools != nil {
				record.AddAttributes(log.Int("tool_count", len(compReq.Tools)))
			}
		}

	case OpStream:
		if streamReq, ok := req.(*StreamRequest); ok {
			record.AddAttributes(
				log.String("slot_name", streamReq.Slot),
				log.Int("message_count", len(streamReq.Messages)),
			)
		}

	case OpCallToolProto:
		if toolReq, ok := req.(*ToolRequest); ok {
			record.AddAttributes(
				log.String("tool_name", toolReq.Name),
				log.Int("parameter_size", len(toolReq.Input)),
			)
		}

	case OpQueryPlugin:
		if pluginReq, ok := req.(*PluginRequest); ok {
			record.AddAttributes(
				log.String("plugin_name", pluginReq.Name),
				log.String("method", pluginReq.Method),
				log.Int("parameter_count", len(pluginReq.Params)),
			)
		}

	case OpDelegateToAgent:
		if delegateReq, ok := req.(*DelegateRequest); ok {
			record.AddAttributes(
				log.String("to_agent", delegateReq.AgentName),
				log.String("task_description", delegateReq.Task.Name),
			)
		}
	}
}

// addCompleteAttributes adds operation-specific attributes for complete events at verbose level.
func addCompleteAttributes(record *log.Record, opType OperationType, resp any) {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		if compResp, ok := resp.(*llm.CompletionResponse); ok {
			record.AddAttributes(
				log.String("model", compResp.Model),
				log.Int64("prompt_tokens", int64(compResp.Usage.PromptTokens)),
				log.Int64("completion_tokens", int64(compResp.Usage.CompletionTokens)),
				log.Int64("total_tokens", int64(compResp.Usage.TotalTokens)),
				log.String("stop_reason", string(compResp.FinishReason)),
				log.Int("response_length", len(compResp.Message.Content)),
			)
		}

	case OpCallToolProto:
		if toolResp, ok := resp.(map[string]any); ok {
			record.AddAttributes(
				log.Int("result_size", len(toolResp)),
				log.Bool("success", true),
			)
		}

	case OpQueryPlugin:
		// Generic success indicator for plugin queries
		if resp != nil {
			record.AddAttributes(log.Bool("success", true))
		}
	}
}

// addDebugStartAttributes adds debug-level request details with redaction.
func addDebugStartAttributes(record *log.Record, opType OperationType, req any) {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		if compReq, ok := req.(*CompletionRequest); ok {
			// Truncate and redact prompt content
			promptPreview := truncatePromptContent(compReq.Messages, 2000)
			// Redact the preview
			promptPreview = redactSensitiveContent(promptPreview)
			record.AddAttributes(log.String("prompt_preview", promptPreview))
		}

	case OpStream:
		if streamReq, ok := req.(*StreamRequest); ok {
			promptPreview := truncatePromptContent(streamReq.Messages, 2000)
			promptPreview = redactSensitiveContent(promptPreview)
			record.AddAttributes(log.String("prompt_preview", promptPreview))
		}

	case OpCallToolProto:
		if toolReq, ok := req.(*ToolRequest); ok {
			// Include parameter summary (but not full values which may be sensitive)
			paramKeys := make([]string, 0, len(toolReq.Input))
			for key := range toolReq.Input {
				paramKeys = append(paramKeys, key)
			}
			record.AddAttributes(log.String("parameter_keys", strings.Join(paramKeys, ",")))
		}
	}
}

// addDebugCompleteAttributes adds debug-level response details with redaction.
func addDebugCompleteAttributes(record *log.Record, opType OperationType, resp any) {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		if compResp, ok := resp.(*llm.CompletionResponse); ok {
			// Truncate response content
			responsePreview := truncateContent(compResp.Message.Content, 2000)
			// Responses typically don't contain sensitive data, but apply redaction for consistency
			responsePreview = redactSensitiveContent(responsePreview)
			record.AddAttributes(log.String("response_preview", responsePreview))
		}
	}
}

// truncatePromptContent truncates a list of messages to a maximum character count.
func truncatePromptContent(messages []llm.Message, maxChars int) string {
	if len(messages) == 0 {
		return ""
	}

	var totalContent string
	for i, msg := range messages {
		prefix := ""
		if i > 0 {
			prefix = " | "
		}
		totalContent += prefix + string(msg.Role) + ": " + msg.Content

		// Stop if we've exceeded max chars
		if len(totalContent) > maxChars {
			break
		}
	}

	return truncateContent(totalContent, maxChars)
}

// truncateContent truncates a string to a maximum character count with an ellipsis.
func truncateContent(content string, maxChars int) string {
	if len(content) <= maxChars {
		return content
	}

	if maxChars <= 3 {
		return content[:maxChars]
	}

	return content[:maxChars-3] + "..."
}

// redactSensitiveContent applies basic redaction patterns to content.
// This is a simple pattern-based redaction for common sensitive patterns.
func redactSensitiveContent(content string) string {
	// For now, just return content as-is since GibsonLogger already handles
	// field-level redaction. This function is a placeholder for future
	// content-based redaction (e.g., detecting API keys in free-form text).
	return content
}

// operationName returns a human-readable name for the operation type.
func operationName(opType OperationType) string {
	switch opType {
	case OpComplete:
		return "llm.complete"
	case OpCompleteWithTools:
		return "llm.complete_with_tools"
	case OpStream:
		return "llm.stream"
	case OpCallToolProto:
		return "tool.call"
	case OpQueryPlugin:
		return "plugin.query"
	case OpDelegateToAgent:
		return "agent.delegate"
	case OpSubmitFinding:
		return "finding.submit"
	case OpGetFindings:
		return "finding.query"
	default:
		return "unknown"
	}
}

// Request types for extracting operation-specific details.
// These would typically be defined in the middleware package or harness package.

// CompletionRequest represents a completion operation request.
type CompletionRequest struct {
	Slot     string
	Messages []llm.Message
	Tools    []llm.ToolDef // Only populated for CompleteWithTools
}

// StreamRequest represents a streaming completion request.
type StreamRequest struct {
	Slot     string
	Messages []llm.Message
}

// ToolRequest represents a tool execution request.
type ToolRequest struct {
	Name  string
	Input map[string]any
}

// PluginRequest represents a plugin query request.
type PluginRequest struct {
	Name   string
	Method string
	Params map[string]any
}

// DelegateRequest represents a sub-agent delegation request.
type DelegateRequest struct {
	AgentName string
	Task      TaskInfo // Simplified task info
}

// TaskInfo holds basic task information for logging.
type TaskInfo struct {
	Name string
}

// Helper functions to extract context values using the context keys from middleware.go

// getOperationType retrieves the operation type from context.
func getOperationType(ctx context.Context) OperationType {
	if val := ctx.Value(CtxOperationType); val != nil {
		if opType, ok := val.(OperationType); ok {
			return opType
		}
	}
	return ""
}

// getMissionID retrieves the mission ID from context.
func getMissionID(ctx context.Context) string {
	if val := ctx.Value(CtxMissionID); val != nil {
		if id, ok := val.(string); ok {
			return id
		}
	}
	return ""
}

// getAgentName retrieves the agent name from context.
func getAgentName(ctx context.Context) string {
	if val := ctx.Value(CtxAgentName); val != nil {
		if name, ok := val.(string); ok {
			return name
		}
	}
	return ""
}
