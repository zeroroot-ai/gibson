// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

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
