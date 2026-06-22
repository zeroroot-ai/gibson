package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// OTelTracingMiddleware creates middleware that traces LLM and tool calls to OpenTelemetry.
// It follows the standard middleware pattern but uses OTel spans
// for distributed tracing with semantic conventions for GenAI observability.
//
// The middleware handles two key operation types:
//   - OpComplete/OpCompleteWithTools: Traced as `gen_ai.chat` spans with GenAI semantic conventions
//   - OpCallToolProto: Traced as `gibson.tool.execute` spans with tool execution attributes
//
// Trace Hierarchy:
// When a tracer and agentSpan are provided, traces are nested under the parent agent execution:
//   - AgentSpan (parent span from orchestrator)
//     ├── gen_ai.chat: LLM completion call with prompt/completion events
//     └── gibson.tool.execute: Tool execution with input/output events
//
// Content Logging:
// The cfg parameter controls whether sensitive content (prompts, completions, tool I/O) is logged
// as span events. When enabled, content is redacted and truncated according to configuration.
//
// Fire-and-Forget Pattern:
// All span creation and event recording runs in goroutines to ensure tracing never blocks
// or fails the underlying operation. This is CRITICAL for production reliability.
//
// Nil Tracer/AgentSpan Behavior:
// If tracer or agentSpan is nil, the middleware acts as a pass-through with zero overhead.
//
// Thread Safety:
// The middleware is safe for concurrent use. Each operation creates independent trace spans.
//
// Parameters:
//   - tracer: OpenTelemetry tracer for span creation (can be nil for pass-through)
//   - agentSpan: Parent AgentSpan for nesting traces (can be nil for pass-through)
//   - cfg: Content logging configuration for prompt/completion capture (can be nil for no content logging)
//
// Returns:
//   - middleware.Middleware: Function that wraps operations with OTel tracing
//
// Example:
//
//	otelMW := observability.OTelTracingMiddleware(tracer, agentSpan, contentCfg)
//	wrapped := otelMW(baseOperation)
func OTelTracingMiddleware(tracer trace.Tracer, agentSpan *AgentSpan, cfg *ContentLoggingConfig) middleware.Middleware {
	return func(next middleware.Operation) middleware.Operation {
		return func(ctx context.Context, req any) (any, error) {
			// Pass-through if tracer or agentSpan is nil
			if tracer == nil || agentSpan == nil {
				return next(ctx, req)
			}

			// Get operation type to determine tracing strategy
			opType := middleware.GetOperationType(ctx)

			// Record start time for duration calculation
			startTime := time.Now()

			// Execute the operation
			resp, err := next(ctx, req)

			// Fire-and-forget trace based on operation type
			// We trace after execution to capture complete information
			switch opType {
			case middleware.OpComplete, middleware.OpCompleteWithTools:
				go traceOTelCompletion(ctx, tracer, agentSpan, cfg, req, resp, err, startTime)

			case middleware.OpCallToolProto:
				go traceOTelToolCall(ctx, tracer, agentSpan, cfg, req, resp, err, startTime)
			}

			// Always return the original result/error
			return resp, err
		}
	}
}

// traceOTelCompletion traces an LLM completion as an OpenTelemetry span with GenAI semantic conventions.
// This runs in a goroutine and logs any errors without propagating them.
//
// The function creates a child span under the agent span and records:
//   - GenAI request attributes (system, model, temperature, max_tokens)
//   - GenAI response attributes (finish_reason, input_tokens, output_tokens)
//   - Span events for prompt and completion content (if content logging enabled)
//   - Span status based on execution error
//   - LLM call statistics in the parent AgentSpan
//
// Content redaction and truncation are applied according to the ContentLoggingConfig.
func traceOTelCompletion(
	ctx context.Context,
	tracer trace.Tracer,
	agentSpan *AgentSpan,
	cfg *ContentLoggingConfig,
	req any,
	resp any,
	execErr error,
	startTime time.Time,
) {
	// Extract the parent context from the agent span
	spanCtx := agentSpan.Context()

	// Create child span under the agent span
	spanCtx, span := tracer.Start(spanCtx, SpanGenAIChat, trace.WithTimestamp(startTime))
	defer span.End()

	// Extract LLM request details
	var messages []llm.Message
	var slot string
	var model string
	var temperature float64
	var maxTokens int
	var provider string

	// Try to extract from CompletionRequest type
	if compReq, ok := req.(*middleware.CompletionRequest); ok {
		slot = compReq.Slot
		messages = compReq.Messages
	}

	// Also try to get from context (set by upstream middleware)
	if ctxMessages := middleware.GetMessages(ctx); ctxMessages != nil && len(messages) == 0 {
		messages = make([]llm.Message, len(ctxMessages))
		for i, msg := range ctxMessages {
			messages[i] = llm.Message{
				Role:    llm.Role(msg.Role),
				Content: msg.Content,
			}
		}
	}

	// If we still don't have slot, try context
	if slot == "" {
		slot = middleware.GetSlotName(ctx)
	}

	// Get provider from context
	provider = middleware.GetProvider(ctx)
	if provider == "" {
		provider = "unknown"
	}

	// Extract response details
	var completion string
	var promptTokens, completionTokens int
	var finishReason string

	if execErr == nil && resp != nil {
		// Try to extract from CompletionResponse
		if compResp, ok := resp.(*llm.CompletionResponse); ok {
			completion = compResp.Message.Content
			model = compResp.Model
			promptTokens = compResp.Usage.PromptTokens
			completionTokens = compResp.Usage.CompletionTokens
			finishReason = string(compResp.FinishReason)

			// Include tool calls in completion if present
			if len(compResp.Message.ToolCalls) > 0 {
				toolCallsJSON, err := json.Marshal(compResp.Message.ToolCalls)
				if err == nil {
					completion += "\n[Tool Calls]: " + string(toolCallsJSON)
				}
			}
		}
	}

	// Handle error case
	if execErr != nil {
		span.RecordError(execErr)
		span.SetStatus(codes.Error, execErr.Error())
		finishReason = "error"
	} else {
		span.SetStatus(codes.Ok, "completion successful")
	}

	// Set GenAI request attributes
	span.SetAttributes(
		attribute.String(GenAISystem, provider),
		attribute.String(GenAIRequestModel, model),
	)

	if temperature > 0 {
		span.SetAttributes(attribute.Float64(GenAIRequestTemperature, temperature))
	}

	if maxTokens > 0 {
		span.SetAttributes(attribute.Int(GenAIRequestMaxTokens, maxTokens))
	}

	// Set GenAI response attributes
	if model != "" {
		span.SetAttributes(attribute.String(GenAIResponseModel, model))
	}

	if finishReason != "" {
		span.SetAttributes(attribute.String(GenAIResponseFinishReason, finishReason))
	}

	// Set token usage attributes
	if promptTokens > 0 {
		span.SetAttributes(attribute.Int(GenAIUsageInputTokens, promptTokens))
	}

	if completionTokens > 0 {
		span.SetAttributes(attribute.Int(GenAIUsageOutputTokens, completionTokens))
	}

	// Set additional Gibson-specific attributes
	span.SetAttributes(
		attribute.String("gibson.llm.slot", slot),
		attribute.String("gibson.agent.name", agentSpan.AgentName),
		attribute.Int64("gibson.llm.duration_ms", time.Since(startTime).Milliseconds()),
	)

	// Add span events for prompt and completion if content logging enabled
	if cfg != nil && cfg.Enabled {
		// Add prompt event
		if len(messages) > 0 {
			prompt := buildFullPromptString(messages)

			// Apply redaction and truncation
			prompt = cfg.Redact(prompt)
			prompt = cfg.Truncate(prompt, cfg.MaxPromptLength)

			span.AddEvent(EventGenAIContentPrompt, trace.WithAttributes(
				attribute.String("prompt", prompt),
				attribute.Int("message_count", len(messages)),
			))
		}

		// Add completion event
		if completion != "" {
			// Apply redaction and truncation
			safeCompletion := cfg.Redact(completion)
			safeCompletion = cfg.Truncate(safeCompletion, cfg.MaxCompletionLength)

			span.AddEvent(EventGenAIContentCompletion, trace.WithAttributes(
				attribute.String("completion", safeCompletion),
				attribute.Int("completion_tokens", completionTokens),
			))
		}
	}

	// Calculate cost (simplified - would use provider-specific pricing in production)
	totalTokens := promptTokens + completionTokens
	var estimatedCost float64
	if totalTokens > 0 {
		// Rough estimate: $0.01 per 1K tokens (varies by provider/model)
		estimatedCost = float64(totalTokens) / 1000.0 * 0.01
	}

	// Update agent span statistics
	agentSpan.AddLLMCall(totalTokens, estimatedCost)

	slog.Debug("otel: traced LLM completion",
		"slot", slot,
		"model", model,
		"prompt_tokens", promptTokens,
		"completion_tokens", completionTokens,
		"finish_reason", finishReason,
		"duration_ms", time.Since(startTime).Milliseconds(),
	)
}

// traceOTelToolCall traces a tool execution as an OpenTelemetry span.
// This runs in a goroutine and logs any errors without propagating them.
//
// The function creates a child span under the agent span and records:
//   - Tool name and execution status
//   - Duration in milliseconds
//   - Span events for input and output (if content logging enabled with IncludeToolIO)
//   - Span status based on execution error
//   - Tool call statistics in the parent AgentSpan
//
// Content redaction and truncation are applied according to the ContentLoggingConfig.
func traceOTelToolCall(
	ctx context.Context,
	tracer trace.Tracer,
	agentSpan *AgentSpan,
	cfg *ContentLoggingConfig,
	req any,
	resp any,
	execErr error,
	startTime time.Time,
) {
	// Extract the parent context from the agent span
	spanCtx := agentSpan.Context()

	// Create child span under the agent span with custom span name
	spanCtx, span := tracer.Start(spanCtx, "gibson.tool.execute", trace.WithTimestamp(startTime))
	defer span.End()

	// Extract tool request details
	var toolName string
	var input map[string]any

	if toolReq, ok := req.(*middleware.ToolRequest); ok {
		toolName = toolReq.Name
		input = toolReq.Input
	}

	// Try context if not in request
	if toolName == "" {
		toolName = middleware.GetToolName(ctx)
	}

	// Extract response
	var output map[string]any
	if execErr == nil && resp != nil {
		if outputMap, ok := resp.(map[string]any); ok {
			output = outputMap
		}
	}

	// Determine status
	var status string
	if execErr != nil {
		status = "error"
		span.RecordError(execErr)
		span.SetStatus(codes.Error, execErr.Error())
	} else {
		status = "success"
		span.SetStatus(codes.Ok, "tool execution successful")
	}

	// Calculate duration
	durationMs := time.Since(startTime).Milliseconds()

	// Set tool attributes
	span.SetAttributes(
		attribute.String("gibson.tool.name", toolName),
		attribute.String("gibson.tool.status", status),
		attribute.Int64("gibson.tool.duration_ms", durationMs),
		attribute.String("gibson.agent.name", agentSpan.AgentName),
	)

	// Add span events for input and output if content logging enabled
	if cfg != nil && cfg.Enabled && cfg.IncludeToolIO {
		// Add tool input event
		if input != nil && len(input) > 0 {
			inputJSON, err := json.Marshal(input)
			if err == nil {
				inputStr := string(inputJSON)

				// Apply redaction and truncation
				inputStr = cfg.Redact(inputStr)
				inputStr = cfg.Truncate(inputStr, cfg.MaxPromptLength) // Reuse prompt length for input

				span.AddEvent(EventGenAIToolCallInput, trace.WithAttributes(
					attribute.String("tool_name", toolName),
					attribute.String("input", inputStr),
				))
			}
		}

		// Add tool output event
		if output != nil && len(output) > 0 {
			outputJSON, err := json.Marshal(output)
			if err == nil {
				outputStr := string(outputJSON)

				// Apply redaction and truncation
				outputStr = cfg.Redact(outputStr)
				outputStr = cfg.Truncate(outputStr, cfg.MaxCompletionLength) // Reuse completion length for output

				span.AddEvent(EventGenAIToolCallOutput, trace.WithAttributes(
					attribute.String("tool_name", toolName),
					attribute.String("output", outputStr),
				))
			}
		} else if execErr != nil {
			// Log error as output
			errorStr := execErr.Error()
			errorStr = cfg.Redact(errorStr)
			errorStr = cfg.Truncate(errorStr, cfg.MaxCompletionLength)

			span.AddEvent(EventGenAIToolCallOutput, trace.WithAttributes(
				attribute.String("tool_name", toolName),
				attribute.String("error", errorStr),
			))
		}
	}

	// Update agent span statistics
	agentSpan.AddToolCall()

	slog.Debug("otel: traced tool call",
		"tool_name", toolName,
		"status", status,
		"duration_ms", durationMs,
	)
}

// buildFullPromptString converts LLM messages into a formatted string for tracing.
// It concatenates messages with role prefixes and includes tool call information.
func buildFullPromptString(messages []llm.Message) string {
	if len(messages) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, msg := range messages {
		if i > 0 {
			sb.WriteString("\n\n---\n\n")
		}

		// Add role prefix in uppercase for clarity
		role := strings.ToUpper(string(msg.Role))
		sb.WriteString(fmt.Sprintf("[%s]:\n%s", role, msg.Content))

		// Include tool calls if present
		if len(msg.ToolCalls) > 0 {
			toolCallsJSON, err := json.Marshal(msg.ToolCalls)
			if err == nil {
				sb.WriteString(fmt.Sprintf("\n[Tool Calls]: %s", string(toolCallsJSON)))
			}
		}

		// Include tool call ID if present
		if msg.ToolCallID != "" {
			sb.WriteString(fmt.Sprintf("\n[Tool Call ID]: %s", msg.ToolCallID))
		}
	}
	return sb.String()
}
