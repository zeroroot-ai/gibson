package middleware

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Span names following OpenTelemetry GenAI semantic conventions
const (
	SpanGenAIChat       = "gen_ai.chat"
	SpanGenAIChatStream = "gen_ai.chat.stream"
	SpanGenAITool       = "gen_ai.tool"
	SpanPluginQuery     = "gibson.plugin.query"
	SpanAgentDelegate   = "gibson.agent.delegate"
	SpanFindingSubmit   = "gibson.finding.submit"
	SpanMemoryGet       = "gibson.memory.get"
	SpanMemorySet       = "gibson.memory.set"
	SpanMemorySearch    = "gibson.memory.search"
)

// Attribute keys
const (
	AttrMissionID        = "gibson.mission.id"
	AttrAgentName        = "gibson.agent.name"
	AttrToolName         = "gibson.tool.name"
	AttrPluginName       = "gibson.plugin.name"
	AttrPluginMethod     = "gibson.plugin.method"
	AttrDelegationTarget = "gibson.delegation.target_agent"
	AttrLLMSlot          = "gibson.llm.slot"
	AttrErrorCode        = "error.code"
	AttrErrorType        = "error.type"
)

// TracingMiddleware creates a middleware that adds OpenTelemetry tracing to all harness operations.
func TracingMiddleware(tracer trace.Tracer) Middleware {
	return func(next Operation) Operation {
		return func(ctx context.Context, req any) (any, error) {
			opType := GetOperationType(ctx)
			spanName := getSpanNameForOperation(opType)

			ctx, span := tracer.Start(ctx, spanName)
			defer span.End()

			// Add base attributes
			addBaseAttributes(span, ctx)
			addPreExecutionAttributes(span, ctx, opType, req)

			// Execute
			resp, err := next(ctx, req)

			// Record result
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				span.SetAttributes(
					attribute.String(AttrErrorCode, getErrorCodeForOperation(opType)),
					attribute.String(AttrErrorType, fmt.Sprintf("%T", err)),
				)
			} else {
				span.SetStatus(codes.Ok, "")
				addPostExecutionAttributes(span, ctx, opType, resp)
			}

			return resp, err
		}
	}
}

func getSpanNameForOperation(opType OperationType) string {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		return SpanGenAIChat
	case OpStream:
		return SpanGenAIChatStream
	case OpCallToolProto:
		return SpanGenAITool
	case OpQueryPlugin:
		return SpanPluginQuery
	case OpDelegateToAgent:
		return SpanAgentDelegate
	case OpSubmitFinding:
		return SpanFindingSubmit
	case OpMemoryGet:
		return SpanMemoryGet
	case OpMemorySet:
		return SpanMemorySet
	case OpMemorySearch:
		return SpanMemorySearch
	default:
		return fmt.Sprintf("gibson.harness.%s", opType)
	}
}

func getErrorCodeForOperation(opType OperationType) string {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		return "COMPLETION_ERROR"
	case OpStream:
		return "STREAM_ERROR"
	case OpCallToolProto:
		return "TOOL_EXECUTION_ERROR"
	case OpQueryPlugin:
		return "PLUGIN_QUERY_ERROR"
	case OpDelegateToAgent:
		return "DELEGATION_ERROR"
	case OpSubmitFinding:
		return "FINDING_SUBMIT_ERROR"
	case OpMemoryGet, OpMemorySet, OpMemorySearch, OpMemoryDelete, OpMemoryList:
		return "MEMORY_ERROR"
	default:
		return "HARNESS_ERROR"
	}
}

func addBaseAttributes(span trace.Span, ctx context.Context) {
	missionID, agentName := GetMissionContext(ctx)
	if missionID != "" {
		span.SetAttributes(attribute.String(AttrMissionID, missionID))
	}
	if agentName != "" {
		span.SetAttributes(attribute.String(AttrAgentName, agentName))
	}
}

func addPreExecutionAttributes(span trace.Span, ctx context.Context, opType OperationType, req any) {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		if slot := GetSlotName(ctx); slot != "" {
			span.SetAttributes(attribute.String(AttrLLMSlot, slot))
		}
		// Add prompt/messages to span for LLM observability
		if messages := GetMessages(ctx); len(messages) > 0 {
			addPromptAttribute(span, messages)
		}
	case OpCallToolProto:
		if toolName := GetToolName(ctx); toolName != "" {
			span.SetAttributes(attribute.String(AttrToolName, toolName))
		}
	case OpQueryPlugin:
		componentName, method := GetPluginInfo(ctx)
		if componentName != "" {
			span.SetAttributes(
				attribute.String(AttrPluginName, componentName),
				attribute.String(AttrPluginMethod, method),
			)
		}
	case OpDelegateToAgent:
		if targetAgent := GetAgentTargetName(ctx); targetAgent != "" {
			span.SetAttributes(attribute.String(AttrDelegationTarget, targetAgent))
		}
	}
}

func addPostExecutionAttributes(span trace.Span, ctx context.Context, opType OperationType, resp any) {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		if resp == nil {
			return
		}

		// Try to extract completion result from various response types
		var result *CompletionResult

		switch v := resp.(type) {
		case *llm.CompletionResponse:
			// Direct type - best case
			result = &CompletionResult{
				ID:           v.ID,
				Model:        v.Model,
				Content:      v.Message.Content,
				FinishReason: string(v.FinishReason),
				InputTokens:  v.Usage.PromptTokens,
				OutputTokens: v.Usage.CompletionTokens,
			}
			if len(v.Message.ToolCalls) > 0 {
				result.ToolCallCount = len(v.Message.ToolCalls)
				result.ToolCallNames = make([]string, len(v.Message.ToolCalls))
				for i, tc := range v.Message.ToolCalls {
					result.ToolCallNames[i] = tc.Name
				}
			}

		case map[string]interface{}:
			// Serialized response - extract fields from map
			result = extractCompletionFromMap(v)

		case *map[string]interface{}:
			// Pointer to serialized response
			if v != nil {
				result = extractCompletionFromMap(*v)
			}
		}

		// Apply attributes if we successfully extracted the result
		if result != nil {
			if result.ID != "" {
				span.SetAttributes(attribute.String("gen_ai.response.id", result.ID))
			}
			if result.Model != "" {
				span.SetAttributes(attribute.String("gen_ai.response.model", result.Model))
			}
			if result.FinishReason != "" {
				span.SetAttributes(attribute.String("gen_ai.response.finish_reason", result.FinishReason))
			}
			if result.InputTokens > 0 {
				span.SetAttributes(attribute.Int("gen_ai.usage.input_tokens", result.InputTokens))
			}
			if result.OutputTokens > 0 {
				span.SetAttributes(attribute.Int("gen_ai.usage.output_tokens", result.OutputTokens))
			}
			if result.Content != "" {
				span.SetAttributes(attribute.String("gen_ai.completion", result.Content))
			}
			if result.ToolCallCount > 0 {
				span.SetAttributes(attribute.Int("gen_ai.response.tool_calls.count", result.ToolCallCount))
				span.SetAttributes(attribute.StringSlice("gen_ai.response.tool_calls.names", result.ToolCallNames))
			}
		}
	}
}

// extractCompletionFromMap extracts completion result from a map[string]interface{}.
// This handles cases where the response was serialized (e.g., through JSON/gRPC).
func extractCompletionFromMap(m map[string]interface{}) *CompletionResult {
	result := &CompletionResult{}

	// Try to extract fields with common naming conventions
	if id, ok := m["id"].(string); ok {
		result.ID = id
	} else if id, ok := m["ID"].(string); ok {
		result.ID = id
	}

	if model, ok := m["model"].(string); ok {
		result.Model = model
	} else if model, ok := m["Model"].(string); ok {
		result.Model = model
	}

	if content, ok := m["content"].(string); ok {
		result.Content = content
	} else if content, ok := m["Content"].(string); ok {
		result.Content = content
	}

	if finishReason, ok := m["finish_reason"].(string); ok {
		result.FinishReason = finishReason
	} else if finishReason, ok := m["FinishReason"].(string); ok {
		result.FinishReason = finishReason
	}

	// Extract usage from nested object or top-level fields
	if usage, ok := m["usage"].(map[string]interface{}); ok {
		if input, ok := usage["input_tokens"].(float64); ok {
			result.InputTokens = int(input)
		} else if input, ok := usage["InputTokens"].(float64); ok {
			result.InputTokens = int(input)
		} else if input, ok := usage["prompt_tokens"].(float64); ok {
			result.InputTokens = int(input)
		}
		if output, ok := usage["output_tokens"].(float64); ok {
			result.OutputTokens = int(output)
		} else if output, ok := usage["OutputTokens"].(float64); ok {
			result.OutputTokens = int(output)
		} else if output, ok := usage["completion_tokens"].(float64); ok {
			result.OutputTokens = int(output)
		}
	} else if usage, ok := m["Usage"].(map[string]interface{}); ok {
		if input, ok := usage["InputTokens"].(float64); ok {
			result.InputTokens = int(input)
		} else if input, ok := usage["PromptTokens"].(float64); ok {
			result.InputTokens = int(input)
		}
		if output, ok := usage["OutputTokens"].(float64); ok {
			result.OutputTokens = int(output)
		} else if output, ok := usage["CompletionTokens"].(float64); ok {
			result.OutputTokens = int(output)
		}
	}

	// Extract tool calls if present
	if toolCalls, ok := m["tool_calls"].([]interface{}); ok {
		result.ToolCallCount = len(toolCalls)
		result.ToolCallNames = make([]string, 0, len(toolCalls))
		for _, tc := range toolCalls {
			if tcMap, ok := tc.(map[string]interface{}); ok {
				if name, ok := tcMap["name"].(string); ok {
					result.ToolCallNames = append(result.ToolCallNames, name)
				}
			}
		}
	}

	// Check if we extracted any useful data
	if result.ID == "" && result.Model == "" && result.Content == "" &&
		result.InputTokens == 0 && result.OutputTokens == 0 {
		return nil
	}

	return result
}

// addPromptAttribute adds the gen_ai.prompt attribute with the messages as text.
// This is called separately from pre-execution because we need the request data.
func addPromptAttribute(span trace.Span, messages []Message) {
	if len(messages) == 0 {
		return
	}

	// Build a simple representation of messages for the prompt
	var promptBuilder string
	for i, msg := range messages {
		if i > 0 {
			promptBuilder += "\n---\n"
		}
		promptBuilder += fmt.Sprintf("[%s]: %s", msg.Role, msg.Content)
	}
	span.SetAttributes(attribute.String("gen_ai.prompt", promptBuilder))
}
