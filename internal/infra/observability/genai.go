package observability

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"go.opentelemetry.io/otel/attribute"
)

// GenAI attribute keys following OpenTelemetry GenAI semantic conventions
// https://opentelemetry.io/docs/specs/semconv/gen-ai/
const (
	// GenAISystem identifies the Generative AI product or service being used
	GenAISystem = "gen_ai.system"

	// GenAIRequestModel is the name of the LLM model requested
	GenAIRequestModel = "gen_ai.request.model"

	// GenAIRequestTemperature is the temperature setting for the LLM request
	GenAIRequestTemperature = "gen_ai.request.temperature"

	// GenAIRequestMaxTokens is the maximum number of tokens requested
	GenAIRequestMaxTokens = "gen_ai.request.max_tokens"

	// GenAIRequestTopP is the top_p sampling parameter
	GenAIRequestTopP = "gen_ai.request.top_p"

	// GenAIResponseModel is the name of the LLM model that generated the response
	GenAIResponseModel = "gen_ai.response.model"

	// GenAIResponseFinishReason indicates why the model stopped generating tokens
	GenAIResponseFinishReason = "gen_ai.response.finish_reason"

	// GenAIUsageInputTokens is the number of tokens in the prompt
	GenAIUsageInputTokens = "gen_ai.usage.input_tokens"

	// GenAIUsageOutputTokens is the number of tokens in the generated completion
	GenAIUsageOutputTokens = "gen_ai.usage.output_tokens"

	// GenAIPrompt is the full prompt sent to the LLM (may contain sensitive data)
	GenAIPrompt = "gen_ai.prompt"

	// GenAICompletion is the full response from the LLM (may contain sensitive data)
	GenAICompletion = "gen_ai.completion"

	// Structured output attribute keys
	// GenAIResponseFormat is the type of response format requested (text, json_object, json_schema)
	GenAIResponseFormat = "gen_ai.response_format"

	// GenAISchemaName is the name of the JSON schema used for structured output
	GenAISchemaName = "gen_ai.schema_name"

	// GenAISchemaStrict indicates whether strict schema validation is enforced
	GenAISchemaStrict = "gen_ai.schema_strict"

	// GenAIValidated indicates whether the response was validated against the schema
	GenAIValidated = "gen_ai.response_validated"

	// GenAIValidationError contains the validation error message if validation failed
	GenAIValidationError = "gen_ai.validation_error"

	// GenAIValidationErrorPath contains the JSON path where validation failed
	GenAIValidationErrorPath = "gen_ai.validation_error_path"

	// GenAIRawJSON contains the raw JSON response before validation (for debugging)
	GenAIRawJSON = "gen_ai.raw_json"

	// Tool-related GenAI attributes following OTel GenAI semantic conventions v1.37+
	// GenAIToolsProvided is the number of tools provided in the request
	GenAIToolsProvided = "gen_ai.request.tools_provided"

	// GenAIToolChoice is the tool choice setting (auto, none, required, specific tool name)
	GenAIToolChoice = "gen_ai.request.tool_choice"

	// GenAIToolCallID is the unique identifier for a tool call
	GenAIToolCallID = "gen_ai.tool_call.id"

	// GenAIToolCallName is the name of the tool being called
	GenAIToolCallName = "gen_ai.tool_call.name"

	// GenAIToolCallArguments contains the arguments passed to the tool (may be JSON)
	GenAIToolCallArguments = "gen_ai.tool_call.arguments"

	// GenAIToolCallResult contains the result returned by the tool
	GenAIToolCallResult = "gen_ai.tool_call.result"
)

// Span name constants for GenAI operations
const (
	// SpanGenAIChat represents a chat completion operation
	SpanGenAIChat = "gen_ai.chat"

	// SpanGenAIChatStream represents a streaming chat completion operation
	SpanGenAIChatStream = "gen_ai.chat.stream"

	// SpanGenAITool represents a tool/function call operation
	SpanGenAITool = "gen_ai.tool"

	// SpanGenAIEmbeddings represents an embeddings generation operation
	SpanGenAIEmbeddings = "gen_ai.embeddings"
)

// Event name constants for content logging
const (
	// EventGenAIContentPrompt is the event name for logging prompt content
	EventGenAIContentPrompt = "gen_ai.content.prompt"

	// EventGenAIContentCompletion is the event name for logging completion content
	EventGenAIContentCompletion = "gen_ai.content.completion"

	// EventGenAIToolCallInput is the event name for logging tool call input
	EventGenAIToolCallInput = "gen_ai.tool_call.input"

	// EventGenAIToolCallOutput is the event name for logging tool call output
	EventGenAIToolCallOutput = "gen_ai.tool_call.output"
)

// RequestAttributes creates OpenTelemetry attributes from an LLM completion request.
// The provider parameter identifies the LLM system (e.g., "openai", "anthropic", "ollama").
func RequestAttributes(req *llm.CompletionRequest, provider string) []attribute.KeyValue {
	if req == nil {
		return []attribute.KeyValue{}
	}

	attrs := []attribute.KeyValue{
		attribute.String(GenAISystem, provider),
		attribute.String(GenAIRequestModel, req.Model),
	}

	// Add optional parameters if they are set
	if req.Temperature > 0 {
		attrs = append(attrs, attribute.Float64(GenAIRequestTemperature, req.Temperature))
	}

	if req.MaxTokens > 0 {
		attrs = append(attrs, attribute.Int(GenAIRequestMaxTokens, req.MaxTokens))
	}

	if req.TopP > 0 {
		attrs = append(attrs, attribute.Float64(GenAIRequestTopP, req.TopP))
	}

	return attrs
}

// ResponseAttributes creates OpenTelemetry attributes from an LLM completion response.
func ResponseAttributes(resp *llm.CompletionResponse) []attribute.KeyValue {
	if resp == nil {
		return []attribute.KeyValue{}
	}

	attrs := []attribute.KeyValue{
		attribute.String(GenAIResponseModel, resp.Model),
		attribute.String(GenAIResponseFinishReason, string(resp.FinishReason)),
	}

	// Add completion content if available
	if resp.Message.Content != "" {
		attrs = append(attrs, attribute.String(GenAICompletion, resp.Message.Content))
	}

	return attrs
}

// UsageAttributes creates OpenTelemetry attributes from token usage statistics.
func UsageAttributes(usage llm.CompletionTokenUsage) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Int(GenAIUsageInputTokens, usage.PromptTokens),
		attribute.Int(GenAIUsageOutputTokens, usage.CompletionTokens),
	}
}

// PromptAttributes creates an attribute containing the full prompt.
// Use with caution as this may contain sensitive data. Consider enabling
// only in development/debug environments.
func PromptAttributes(req *llm.CompletionRequest) []attribute.KeyValue {
	if req == nil || len(req.Messages) == 0 {
		return []attribute.KeyValue{}
	}

	// Concatenate all message contents for the prompt attribute
	var promptBuilder string
	for i, msg := range req.Messages {
		if i > 0 {
			promptBuilder += "\n"
		}
		promptBuilder += fmt.Sprintf("[%s] %s", msg.Role, msg.Content)
	}

	return []attribute.KeyValue{
		attribute.String(GenAIPrompt, promptBuilder),
	}
}

// ToolCallAttributes creates OpenTelemetry attributes from tool calls in a response.
// This function returns the number of tools provided and summarizes tool call information
// for use as span attributes. Large tool call details should be logged as events, not attributes.
//
// The function limits the number of tool calls included in attributes to avoid
// overwhelming the telemetry system. For detailed tool call information, use events
// with SingleToolCallAttributes.
func ToolCallAttributes(toolCalls []llm.ToolCall) []attribute.KeyValue {
	if len(toolCalls) == 0 {
		return []attribute.KeyValue{}
	}

	attrs := []attribute.KeyValue{
		attribute.Int(GenAIToolsProvided, len(toolCalls)),
	}

	// Include up to 3 tool call names to avoid overwhelming attributes
	// More detailed information should be logged as events
	const maxToolCallsInAttributes = 3
	for i, tc := range toolCalls {
		if i >= maxToolCallsInAttributes {
			break
		}

		// Add tool call ID and name for each tool call
		// Use indexed attribute names to differentiate multiple tool calls
		attrs = append(attrs,
			attribute.String(fmt.Sprintf("%s.%d", GenAIToolCallID, i), tc.ID),
			attribute.String(fmt.Sprintf("%s.%d", GenAIToolCallName, i), tc.Name),
		)
	}

	return attrs
}

// ToolChoiceAttributes creates OpenTelemetry attributes for the tool choice setting.
// The toolChoice parameter indicates how the LLM should handle tool selection:
// - "auto": LLM decides whether to use tools
// - "none": LLM should not use any tools
// - "required": LLM must use at least one tool
// - specific tool name: LLM must use the named tool
func ToolChoiceAttributes(toolChoice string) []attribute.KeyValue {
	if toolChoice == "" {
		return []attribute.KeyValue{}
	}

	return []attribute.KeyValue{
		attribute.String(GenAIToolChoice, toolChoice),
	}
}

// SingleToolCallAttributes creates OpenTelemetry attributes for a single tool call.
// This is useful for logging individual tool call details as span events.
//
// The arguments parameter may contain JSON. Large arguments should be truncated
// before calling this function to avoid overwhelming the telemetry system.
// Consider using a maximum size of 1KB for arguments in attributes.
func SingleToolCallAttributes(id, name, arguments string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GenAIToolCallID, id),
		attribute.String(GenAIToolCallName, name),
	}

	// Only include arguments if they're not too large
	// Arguments larger than 1KB should be logged separately or truncated
	const maxArgumentsSize = 1024
	if arguments != "" && len(arguments) <= maxArgumentsSize {
		attrs = append(attrs, attribute.String(GenAIToolCallArguments, arguments))
	} else if arguments != "" {
		// Truncate and add indicator
		truncated := arguments[:maxArgumentsSize]
		attrs = append(attrs, attribute.String(GenAIToolCallArguments, truncated+"... [truncated]"))
	}

	return attrs
}

// ToolResultAttributes creates OpenTelemetry attributes for a tool execution result.
// This is useful for logging tool results as span events.
//
// The result parameter contains the output from the tool execution. Large results
// should be truncated before calling this function or the truncated parameter should
// be set to true to indicate that truncation has already occurred.
//
// Consider using a maximum size of 2KB for results in attributes. Larger results
// should be logged to structured logs instead.
func ToolResultAttributes(id, name, result string, truncated bool) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GenAIToolCallID, id),
		attribute.String(GenAIToolCallName, name),
	}

	// Include result, potentially with truncation indicator
	const maxResultSize = 2048
	if result != "" {
		if len(result) > maxResultSize && !truncated {
			// Truncate if not already truncated
			result = result[:maxResultSize] + "... [truncated]"
			truncated = true
		}
		attrs = append(attrs, attribute.String(GenAIToolCallResult, result))
	}

	// Add truncation indicator if result was truncated
	if truncated {
		attrs = append(attrs, attribute.Bool("gen_ai.tool_call.result_truncated", true))
	}

	return attrs
}
