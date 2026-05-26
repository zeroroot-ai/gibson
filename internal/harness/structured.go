package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/schema"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// Structured output tracing attribute keys (aligned with observability.GenAI* constants)
const (
	genAIResponseFormat      = "gen_ai.response_format"
	genAISchemaName          = "gen_ai.schema_name"
	genAISchemaStrict        = "gen_ai.schema_strict"
	genAIValidated           = "gen_ai.response_validated"
	genAIValidationError     = "gen_ai.validation_error"
	genAIValidationErrorPath = "gen_ai.validation_error_path"
	genAIRawJSON             = "gen_ai.raw_json"
)

// CompleteStructured performs a completion and unmarshals the response to type T.
// It generates a JSON schema from T using reflection, requests structured output
// from the provider, validates the response, and returns a pointer to the unmarshaled result.
//
// Type Parameter:
//   - T: The Go type to unmarshal the structured output into. Must be a struct type.
//
// Parameters:
//   - ctx: Context for cancellation, timeout, and distributed tracing
//   - h: The agent harness providing access to LLM providers and slot management
//   - slot: Name of the LLM slot to use (e.g., "primary", "reasoning")
//   - messages: Conversation history with system, user, and assistant messages
//   - opts: Optional configuration (temperature, max tokens, etc.)
//
// Returns:
//   - *T: Pointer to the unmarshaled structured output
//   - error: Non-nil if operation fails (provider doesn't support structured output,
//     validation fails, unmarshaling fails, etc.)
//
// Error Handling:
//   - Returns llm.StructuredOutputError if provider doesn't support structured output
//   - Returns llm.UnmarshalError if JSON is valid but doesn't match type T
//   - Returns llm.ParseError if provider returns invalid JSON
//   - All errors include raw JSON response for debugging
//
// Requirements Satisfied:
//   - 3.1: Unmarshals response into type T
//   - 3.2: Returns typed error with raw JSON on unmarshal failure
//   - 3.3: Returns *T (pointer to type T), not string
//
// Example:
//
//	type AnalysisResult struct {
//	    Severity   string   `json:"severity"`
//	    Findings   []string `json:"findings"`
//	    Confidence float64  `json:"confidence"`
//	}
//
//	result, err := CompleteStructured[AnalysisResult](
//	    ctx, harness, "primary",
//	    []llm.Message{llm.NewUserMessage("Analyze this code")},
//	    WithTemperature(0.2),
//	)
//	if err != nil {
//	    var unmarshalErr *llm.UnmarshalError
//	    if errors.As(err, &unmarshalErr) {
//	        log.Printf("Raw JSON: %s", unmarshalErr.Raw)
//	    }
//	    return err
//	}
//	fmt.Printf("Severity: %s, Confidence: %.2f\n", result.Severity, result.Confidence)
func CompleteStructured[T any](
	ctx context.Context,
	h *DefaultAgentHarness,
	slot string,
	messages []llm.Message,
	opts ...CompletionOption,
) (*T, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CompleteStructured")
	defer span.End()

	// Generate schema from type T using reflection
	jsonSchema := SchemaFromType[T]()
	typeName := TypeName[T]()

	h.logger.Debug("generating structured output schema",
		"type", typeName,
		"slot", slot)

	// Convert internal schema to SDK schema format
	sdkSchema := convertToSDKSchema(jsonSchema)

	// Build ResponseFormat with strict validation
	format := &types.ResponseFormat{
		Type:   types.ResponseFormatJSONSchema,
		Name:   typeName,
		Schema: sdkSchema,
		Strict: true,
	}

	// Validate the response format
	if err := format.Validate(); err != nil {
		h.logger.Error("invalid response format",
			"type", typeName,
			"error", err)
		return nil, fmt.Errorf("invalid response format for type %s: %w", typeName, err)
	}

	// Build completion request with structured output
	req := llm.CompletionRequest{
		Messages:       messages,
		ResponseFormat: format,
	}

	// Apply completion options
	options := applyOptions(opts...)
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		// Prepend system message if provided
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Add structured output tracing attributes to the span
	span.SetAttributes(
		attribute.String(genAIResponseFormat, string(format.Type)),
		attribute.String(genAISchemaName, format.Name),
		attribute.Bool(genAISchemaStrict, format.Strict),
	)

	// Resolve slot to provider and model
	// Create slot definition for the named slot
	slotDef := agent.NewSlotDefinition(slot, "LLM slot for structured output", true)
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, nil)
	if err != nil {
		h.logger.Error("failed to resolve slot",
			"slot", slot,
			"type", typeName,
			"error", err)
		return nil, fmt.Errorf("failed to resolve slot %s: %w", slot, err)
	}
	req.Model = modelInfo.Name

	h.logger.Debug("resolved slot for structured output",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"type", typeName)

	// Check if provider supports structured output
	structuredProvider, ok := provider.(llm.StructuredOutputProvider)
	if !ok {
		h.logger.Error("provider does not support structured output",
			"slot", slot,
			"provider", provider.Name(),
			"type", typeName)
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: provider %s", llm.ErrStructuredOutputNotSupportedSentinel, provider.Name()),
		)
	}

	// Verify provider supports json_schema format
	if !structuredProvider.SupportsStructuredOutput(format.Type) {
		h.logger.Error("provider does not support json_schema format",
			"slot", slot,
			"provider", provider.Name(),
			"format", format.Type,
			"type", typeName)
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: format %s not supported by provider %s",
				llm.ErrStructuredOutputNotSupportedSentinel, format.Type, provider.Name()),
		)
	}

	h.logger.Debug("calling provider for structured completion",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"type", typeName)

	// Call provider's structured output method
	resp, err := structuredProvider.CompleteStructured(ctx, req)
	if err != nil {
		h.logger.Error("structured completion failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"type", typeName,
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
			"slot":     slot,
			"provider": provider.Name(),
			"model":    modelInfo.Name,
			"type":     typeName,
			"status":   "failed",
		})

		return nil, err
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	if err := h.tokenUsage.RecordUsage(scope, provider.Name(), resp.Model, tokenUsage); err != nil {
		h.logger.Warn("failed to record token usage",
			"error", err)
		// Don't fail the request if tracking fails
	}

	// Unmarshal response to type T
	var result T
	if err := json.Unmarshal([]byte(resp.RawJSON), &result); err != nil {
		h.logger.Error("failed to unmarshal structured output",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"type", typeName,
			"error", err,
			"raw_json_length", len(resp.RawJSON))

		// Record validation failure in tracing
		span.SetAttributes(
			attribute.Bool(genAIValidated, false),
			attribute.String(genAIValidationError, err.Error()),
			attribute.String(genAIRawJSON, resp.RawJSON),
		)

		// Note: SDK schema doesn't have SchemaValidationError type
		// Extract path from error message if possible
		// var schemaErr *schema.SchemaValidationError
		// if errors.As(err, &schemaErr) {
		//	 span.SetAttributes(attribute.String(genAIValidationErrorPath, schemaErr.Path))
		// }

		span.SetStatus(codes.Error, "validation failed")

		// Record failure metrics
		h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
			"slot":     slot,
			"provider": provider.Name(),
			"model":    modelInfo.Name,
			"type":     typeName,
			"status":   "unmarshal_failed",
		})

		// Return detailed unmarshal error with raw JSON for debugging
		return nil, llm.NewUnmarshalError(provider.Name(), resp.RawJSON, typeName, err)
	}

	// Record successful validation in tracing
	span.SetAttributes(attribute.Bool(genAIValidated, true))

	// Record success metrics
	h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
		"type":     typeName,
		"status":   "success",
	})
	h.metrics.RecordCounter("llm.tokens.input", int64(resp.Usage.PromptTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
	})
	h.metrics.RecordCounter("llm.tokens.output", int64(resp.Usage.CompletionTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
	})

	h.logger.Debug("structured completion successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"type", typeName,
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	return &result, nil
}

// StructuredResponse contains the result of a structured completion request
// when using explicit schemas instead of the generic CompleteStructured[T] method.
type StructuredResponse struct {
	// Data contains the parsed JSON as a map
	Data map[string]any
	// RawJSON contains the raw JSON string from the LLM response
	RawJSON string
	// TokenUsage contains token counts for the request
	TokenUsage llm.TokenUsage
}

// CompleteWithSchema performs a structured completion using an explicit schema.
// Unlike CompleteStructured[T], this method works with dynamic schemas at runtime
// and returns both the raw JSON and a parsed map[string]any.
//
// Parameters:
//   - ctx: Context for cancellation, timeout, and distributed tracing
//   - slot: Name of the LLM slot to use (e.g., "primary", "reasoning")
//   - messages: Conversation history with system, user, and assistant messages
//   - format: ResponseFormat with explicit JSON schema (must not be nil)
//   - opts: Optional configuration (temperature, max tokens, etc.)
//
// Returns:
//   - *StructuredResponse: Contains both raw JSON and parsed map[string]any, plus token usage
//   - error: Non-nil if operation fails (nil format, provider doesn't support structured output,
//     validation fails, parsing fails, etc.)
//
// Error Handling:
//   - Returns error if format is nil (schema required)
//   - Returns llm.StructuredOutputError if provider doesn't support structured output
//   - Returns llm.ParseError if provider returns invalid JSON
//   - All errors include raw JSON response for debugging when available
//
// Requirements Satisfied:
//   - 3.4: Returns both raw JSON and parsed map[string]any
//
// Example:
//
//	schema := &types.ResponseFormat{
//	    Type:   types.ResponseFormatJSONSchema,
//	    Name:   "analysis_result",
//	    Schema: &types.JSONSchema{
//	        Type: "object",
//	        Properties: map[string]*types.JSONSchema{
//	            "severity": {Type: "string"},
//	            "findings": {Type: "array", Items: &types.JSONSchema{Type: "string"}},
//	        },
//	        Required: []string{"severity", "findings"},
//	    },
//	    Strict: true,
//	}
//
//	resp, err := harness.CompleteWithSchema(
//	    ctx, "primary",
//	    []llm.Message{llm.NewUserMessage("Analyze this code")},
//	    schema,
//	    WithTemperature(0.2),
//	)
//	if err != nil {
//	    return err
//	}
//	severity := resp.Data["severity"].(string)
//	fmt.Printf("Raw JSON: %s\n", resp.RawJSON)
func (h *DefaultAgentHarness) CompleteWithSchema(
	ctx context.Context,
	slot string,
	messages []llm.Message,
	format *types.ResponseFormat,
	opts ...CompletionOption,
) (*StructuredResponse, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CompleteWithSchema")
	defer span.End()

	// Validate that format is provided
	if format == nil {
		h.logger.Error("response format required for CompleteWithSchema",
			"slot", slot)
		return nil, llm.NewStructuredOutputError("complete", "", "",
			fmt.Errorf("%w: format parameter cannot be nil", llm.ErrSchemaRequiredSentinel))
	}

	h.logger.Debug("performing structured completion with explicit schema",
		"slot", slot,
		"format_type", format.Type,
		"format_name", format.Name)

	// Validate the response format
	if err := format.Validate(); err != nil {
		h.logger.Error("invalid response format",
			"slot", slot,
			"format_name", format.Name,
			"error", err)
		return nil, fmt.Errorf("invalid response format %s: %w", format.Name, err)
	}

	// Build completion request with structured output
	req := llm.CompletionRequest{
		Messages:       messages,
		ResponseFormat: format,
	}

	// Apply completion options
	options := applyOptions(opts...)
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		// Prepend system message if provided
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Add structured output tracing attributes to the span
	span.SetAttributes(
		attribute.String(genAIResponseFormat, string(format.Type)),
		attribute.String(genAISchemaName, format.Name),
		attribute.Bool(genAISchemaStrict, format.Strict),
	)

	// Resolve slot to provider and model
	slotDef := agent.NewSlotDefinition(slot, "LLM slot for structured output", true)
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, nil)
	if err != nil {
		h.logger.Error("failed to resolve slot",
			"slot", slot,
			"format_name", format.Name,
			"error", err)
		return nil, fmt.Errorf("failed to resolve slot %s: %w", slot, err)
	}
	req.Model = modelInfo.Name

	h.logger.Debug("resolved slot for structured output",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"format_name", format.Name)

	// Check if provider supports structured output
	structuredProvider, ok := provider.(llm.StructuredOutputProvider)
	if !ok {
		h.logger.Error("provider does not support structured output",
			"slot", slot,
			"provider", provider.Name(),
			"format_name", format.Name)
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: provider %s", llm.ErrStructuredOutputNotSupportedSentinel, provider.Name()),
		)
	}

	// Verify provider supports the requested format type
	if !structuredProvider.SupportsStructuredOutput(format.Type) {
		h.logger.Error("provider does not support format type",
			"slot", slot,
			"provider", provider.Name(),
			"format_type", format.Type,
			"format_name", format.Name)
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: format %s not supported by provider %s",
				llm.ErrStructuredOutputNotSupportedSentinel, format.Type, provider.Name()),
		)
	}

	h.logger.Debug("calling provider for structured completion",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"format_name", format.Name)

	// Call provider's structured output method
	resp, err := structuredProvider.CompleteStructured(ctx, req)
	if err != nil {
		h.logger.Error("structured completion failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"format_name", format.Name,
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
			"slot":     slot,
			"provider": provider.Name(),
			"model":    modelInfo.Name,
			"format":   format.Name,
			"status":   "failed",
		})

		return nil, err
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	if err := h.tokenUsage.RecordUsage(scope, provider.Name(), resp.Model, tokenUsage); err != nil {
		h.logger.Warn("failed to record token usage",
			"error", err)
		// Don't fail the request if tracking fails
	}

	// Parse response to map[string]any
	var data map[string]any
	if err := json.Unmarshal([]byte(resp.RawJSON), &data); err != nil {
		h.logger.Error("failed to parse structured output",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"format_name", format.Name,
			"error", err,
			"raw_json_length", len(resp.RawJSON))

		// Record validation failure in tracing
		span.SetAttributes(
			attribute.Bool(genAIValidated, false),
			attribute.String(genAIValidationError, err.Error()),
			attribute.String(genAIRawJSON, resp.RawJSON),
		)
		span.SetStatus(codes.Error, "parse failed")

		// Record failure metrics
		h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
			"slot":     slot,
			"provider": provider.Name(),
			"model":    modelInfo.Name,
			"format":   format.Name,
			"status":   "parse_failed",
		})

		// Return detailed parse error with raw JSON for debugging
		return nil, llm.NewParseError(provider.Name(), resp.RawJSON, 0, err)
	}

	// Record successful validation in tracing
	span.SetAttributes(attribute.Bool(genAIValidated, true))

	// Record success metrics
	h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
		"format":   format.Name,
		"status":   "success",
	})
	h.metrics.RecordCounter("llm.tokens.input", int64(resp.Usage.PromptTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
	})
	h.metrics.RecordCounter("llm.tokens.output", int64(resp.Usage.CompletionTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
	})

	h.logger.Debug("structured completion successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"format_name", format.Name,
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	return &StructuredResponse{
		Data:       data,
		RawJSON:    resp.RawJSON,
		TokenUsage: tokenUsage,
	}, nil
}

// convertToSDKSchema converts internal schema.JSON to sdk/types.JSONSchema.
// This handles the translation between the internal schema representation used
// for generation and the SDK type used in the public API.
func convertToSDKSchema(s schema.JSON) *types.JSONSchema {
	if s.Type == "" {
		return nil
	}

	result := &types.JSONSchema{
		Type:        s.Type,
		Description: s.Description,
		Required:    s.Required,
	}

	// Convert properties
	if len(s.Properties) > 0 {
		result.Properties = make(map[string]*types.JSONSchema)
		for name, field := range s.Properties {
			result.Properties[name] = convertSchemaFieldToSDK(field)
		}
	}

	// Convert items for array types
	if s.Items != nil {
		result.Items = convertSchemaFieldToSDK(*s.Items)
	}

	// Note: SDK schema.JSON doesn't have AdditionalProperties field

	return result
}

// convertSchemaFieldToSDK converts internal schema.JSON to sdk/types.JSONSchema.
// This recursive function handles nested schemas and all field types.
func convertSchemaFieldToSDK(f schema.JSON) *types.JSONSchema {
	result := &types.JSONSchema{
		Type:        f.Type,
		Description: f.Description,
		Format:      f.Format,
		Pattern:     f.Pattern,
		Minimum:     f.Minimum,
		Maximum:     f.Maximum,
		MinLength:   f.MinLength,
		MaxLength:   f.MaxLength,
		Required:    f.Required,
	}

	// Convert enum ([]string to []any)
	if len(f.Enum) > 0 {
		result.Enum = make([]any, len(f.Enum))
		for i, v := range f.Enum {
			result.Enum[i] = v
		}
	}

	// Convert nested properties
	if len(f.Properties) > 0 {
		result.Properties = make(map[string]*types.JSONSchema)
		for name, nestedField := range f.Properties {
			result.Properties[name] = convertSchemaFieldToSDK(nestedField)
		}
	}

	// Convert items for array types
	if f.Items != nil {
		result.Items = convertSchemaFieldToSDK(*f.Items)
	}

	return result
}

// CompleteStructuredAny performs a completion with provider-native structured output.
// This is the SDK interface method that uses reflection to generate schema from the
// provided struct type. Unlike the generic CompleteStructured[T] function, this method
// takes the schema as an any type and returns any, making it compatible with the SDK interface.
//
// The schema parameter should be an instance of the struct type you want the response
// to conform to (e.g., MyStruct{} or &MyStruct{}). The method will:
// 1. Generate a JSON schema from the struct type using reflection
// 2. Request structured output from the provider using native mechanisms
// 3. Parse and validate the response
// 4. Return a pointer to a new instance populated with the response data
//
// For Anthropic: uses the tool_use pattern (schema becomes a tool definition)
// For OpenAI: uses response_format with json_schema
//
// The prompt should be natural language - no JSON format instructions needed.
func (h *DefaultAgentHarness) CompleteStructuredAny(
	ctx context.Context,
	slot string,
	messages []llm.Message,
	schemaType any,
	opts ...CompletionOption,
) (any, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CompleteStructuredAny")
	defer span.End()

	var sdkSchema *types.JSONSchema
	var typeName string
	var localType reflect.Type // Only set for local Go struct types, nil for remote/map schemas

	// Check if schemaType is already a map (JSON schema passed directly from callback/remote agent)
	if schemaMap, ok := schemaType.(map[string]any); ok {
		// Schema was passed as JSON from remote agent - convert directly to SDK schema
		// In this case, we return map[string]any since we don't have the original Go type
		typeName = "RemoteSchema"
		if name, ok := schemaMap["name"].(string); ok && name != "" {
			typeName = name
		}

		// Debug: log the received schema
		schemaJSON, _ := json.Marshal(schemaMap)
		h.logger.Info("received schema from remote agent",
			"schema_json", string(schemaJSON),
			"has_type", schemaMap["type"] != nil,
			"type_value", schemaMap["type"])

		sdkSchema = mapToJSONSchema(schemaMap)
		// localType remains nil - we'll return map[string]any

		h.logger.Debug("using pre-built schema from remote agent",
			"type", typeName,
			"slot", slot)
	} else {
		// Use reflection to get the type of the schema (local Go struct)
		t := reflect.TypeOf(schemaType)
		if t == nil {
			return nil, fmt.Errorf("schema type cannot be nil")
		}

		// If it's a pointer, get the element type
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}

		localType = t // Save for unmarshaling later

		// Generate schema from the type
		jsonSchema := schemaFromReflectType(t)
		typeName = t.Name()
		if typeName == "" {
			typeName = "AnonymousType"
		}

		h.logger.Debug("generating structured output schema from type",
			"type", typeName,
			"slot", slot)

		// Convert internal schema to SDK schema format
		sdkSchema = convertToSDKSchema(jsonSchema)
	}

	// Build ResponseFormat with strict validation
	format := &types.ResponseFormat{
		Type:   types.ResponseFormatJSONSchema,
		Name:   typeName,
		Schema: sdkSchema,
		Strict: true,
	}

	// Validate the response format
	if err := format.Validate(); err != nil {
		h.logger.Error("invalid response format",
			"type", typeName,
			"error", err)
		return nil, fmt.Errorf("invalid response format for type %s: %w", typeName, err)
	}

	// Build completion request with structured output
	req := llm.CompletionRequest{
		Messages:       messages,
		ResponseFormat: format,
	}

	// Apply completion options
	options := applyOptions(opts...)
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Add structured output and prompt tracing attributes
	span.SetAttributes(
		attribute.String(genAIResponseFormat, string(format.Type)),
		attribute.String(genAISchemaName, format.Name),
		attribute.Bool(genAISchemaStrict, format.Strict),
		attribute.String("gen_ai.prompt", formatMessagesForPrompt(messages)),
		attribute.String("gen_ai.request.model", slot),
		attribute.Int("gen_ai.request.message_count", len(messages)),
	)

	// Resolve slot to provider and model
	slotDef := agent.NewSlotDefinition(slot, "LLM slot for structured output", true)
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, nil)
	if err != nil {
		h.logger.Error("failed to resolve slot",
			"slot", slot,
			"type", typeName,
			"error", err)
		return nil, fmt.Errorf("failed to resolve slot %s: %w", slot, err)
	}
	req.Model = modelInfo.Name

	h.logger.Debug("resolved slot for structured output",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"type", typeName)

	// Check if provider supports structured output
	structuredProvider, ok := provider.(llm.StructuredOutputProvider)
	if !ok {
		h.logger.Error("provider does not support structured output",
			"slot", slot,
			"provider", provider.Name(),
			"type", typeName)
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: provider %s", llm.ErrStructuredOutputNotSupportedSentinel, provider.Name()),
		)
	}

	// Verify provider supports the requested format type
	if !structuredProvider.SupportsStructuredOutput(format.Type) {
		h.logger.Error("provider does not support format type",
			"slot", slot,
			"provider", provider.Name(),
			"format_type", format.Type,
			"type", typeName)
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: format %s not supported by provider %s",
				llm.ErrStructuredOutputNotSupportedSentinel, format.Type, provider.Name()),
		)
	}

	h.logger.Debug("calling provider for structured completion",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"type", typeName)

	// Call provider's structured output method
	resp, err := structuredProvider.CompleteStructured(ctx, req)
	if err != nil {
		h.logger.Error("structured completion failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"type", typeName,
			"error", err)

		// Record validation failure in span
		span.SetAttributes(
			attribute.Bool(genAIValidated, false),
			attribute.String(genAIValidationError, err.Error()),
		)

		h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
			"slot":     slot,
			"provider": provider.Name(),
			"model":    modelInfo.Name,
			"type":     typeName,
			"status":   "failed",
		})
		return nil, err
	}

	// Record validation success
	span.SetAttributes(attribute.Bool(genAIValidated, true))

	// Unmarshal the response based on whether we have a local Go type or remote schema
	var result any
	if localType != nil {
		// Local Go struct - unmarshal to the specific type
		resultPtr := reflect.New(localType)
		if err := json.Unmarshal([]byte(resp.RawJSON), resultPtr.Interface()); err != nil {
			h.logger.Error("failed to unmarshal structured response",
				"slot", slot,
				"provider", provider.Name(),
				"model", modelInfo.Name,
				"type", typeName,
				"error", err)

			span.SetAttributes(
				attribute.Bool(genAIValidated, false),
				attribute.String(genAIValidationError, err.Error()),
				attribute.String(genAIRawJSON, resp.RawJSON),
			)

			h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
				"slot":     slot,
				"provider": provider.Name(),
				"model":    modelInfo.Name,
				"type":     typeName,
				"status":   "parse_failed",
			})
			return nil, llm.NewUnmarshalError(provider.Name(), resp.RawJSON, typeName, err)
		}
		result = resultPtr.Interface()
	} else {
		// Remote schema (map[string]any) - return the JSON as map[string]any
		// The agent will unmarshal to its local Go type on its side
		var mapResult map[string]any
		if err := json.Unmarshal([]byte(resp.RawJSON), &mapResult); err != nil {
			h.logger.Error("failed to parse structured response as map",
				"slot", slot,
				"provider", provider.Name(),
				"model", modelInfo.Name,
				"type", typeName,
				"error", err)

			span.SetAttributes(
				attribute.Bool(genAIValidated, false),
				attribute.String(genAIValidationError, err.Error()),
				attribute.String(genAIRawJSON, resp.RawJSON),
			)

			h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
				"slot":     slot,
				"provider": provider.Name(),
				"model":    modelInfo.Name,
				"type":     typeName,
				"status":   "parse_failed",
			})
			return nil, llm.NewParseError(provider.Name(), resp.RawJSON, 0, err)
		}
		result = mapResult
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	if err := h.tokenUsage.RecordUsage(scope, provider.Name(), modelInfo.Name, tokenUsage); err != nil {
		h.logger.Warn("failed to record token usage",
			"error", err)
		// Don't fail the request if tracking fails
	}

	// Record success metrics
	h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
		"type":     typeName,
		"status":   "success",
	})

	h.logger.Debug("structured completion successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"type", typeName,
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	// Add response attributes for observability
	span.SetAttributes(
		attribute.String("gen_ai.completion", resp.RawJSON),
		attribute.String("gen_ai.response.model", modelInfo.Name),
		attribute.Int("gen_ai.usage.input_tokens", resp.Usage.PromptTokens),
		attribute.Int("gen_ai.usage.output_tokens", resp.Usage.CompletionTokens),
	)

	return result, nil
}

// CompleteStructured is an alias for CompleteStructuredAny for SDK interface compatibility.
// See CompleteStructuredAny for full documentation.
func (h *DefaultAgentHarness) CompleteStructured(
	ctx context.Context,
	slot string,
	messages []llm.Message,
	schemaType any,
	opts ...CompletionOption,
) (any, error) {
	return h.CompleteStructuredAny(ctx, slot, messages, schemaType, opts...)
}

// CompleteStructuredAnyWithUsage performs structured completion and returns token usage.
// This method is identical to CompleteStructuredAny but returns a StructuredCompletionResult
// containing the parsed result, model name, raw JSON, and token usage information.
//
// This is useful for orchestration systems that need to track token usage for cost
// accounting and observability (e.g., Langfuse integration).
func (h *DefaultAgentHarness) CompleteStructuredAnyWithUsage(
	ctx context.Context,
	slot string,
	messages []llm.Message,
	schemaType any,
	opts ...CompletionOption,
) (*StructuredCompletionResult, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CompleteStructuredAnyWithUsage")
	defer span.End()

	var sdkSchema *types.JSONSchema
	var typeName string
	var localType reflect.Type

	// Check if schemaType is already a map (JSON schema passed directly from callback/remote agent)
	if schemaMap, ok := schemaType.(map[string]any); ok {
		typeName = "RemoteSchema"
		if name, ok := schemaMap["name"].(string); ok && name != "" {
			typeName = name
		}
		sdkSchema = mapToJSONSchema(schemaMap)
	} else {
		t := reflect.TypeOf(schemaType)
		if t == nil {
			return nil, fmt.Errorf("schema type cannot be nil")
		}
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		localType = t
		jsonSchema := schemaFromReflectType(t)
		typeName = t.Name()
		if typeName == "" {
			typeName = "AnonymousType"
		}
		sdkSchema = convertToSDKSchema(jsonSchema)
	}

	// Build ResponseFormat with strict validation
	format := &types.ResponseFormat{
		Type:   types.ResponseFormatJSONSchema,
		Name:   typeName,
		Schema: sdkSchema,
		Strict: true,
	}

	if err := format.Validate(); err != nil {
		return nil, fmt.Errorf("invalid response format for type %s: %w", typeName, err)
	}

	// Build completion request with structured output
	req := llm.CompletionRequest{
		Messages:       messages,
		ResponseFormat: format,
	}

	// Apply completion options
	options := applyOptions(opts...)
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Resolve slot to provider and model
	slotDef := agent.NewSlotDefinition(slot, "LLM slot for structured output", true)
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve slot %s: %w", slot, err)
	}
	req.Model = modelInfo.Name

	// Check if provider supports structured output
	structuredProvider, ok := provider.(llm.StructuredOutputProvider)
	if !ok {
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: provider %s", llm.ErrStructuredOutputNotSupportedSentinel, provider.Name()),
		)
	}

	if !structuredProvider.SupportsStructuredOutput(format.Type) {
		return nil, llm.NewStructuredOutputError(
			"complete",
			provider.Name(),
			"",
			fmt.Errorf("%w: format %s not supported by provider %s",
				llm.ErrStructuredOutputNotSupportedSentinel, format.Type, provider.Name()),
		)
	}

	// Call provider's structured output method
	resp, err := structuredProvider.CompleteStructured(ctx, req)
	if err != nil {
		h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
			"slot":     slot,
			"provider": provider.Name(),
			"model":    modelInfo.Name,
			"type":     typeName,
			"status":   "failed",
		})
		return nil, err
	}

	// Unmarshal the response
	var result any
	if localType != nil {
		resultPtr := reflect.New(localType)
		if err := json.Unmarshal([]byte(resp.RawJSON), resultPtr.Interface()); err != nil {
			return nil, llm.NewUnmarshalError(provider.Name(), resp.RawJSON, typeName, err)
		}
		result = resultPtr.Interface()
	} else {
		var mapResult map[string]any
		if err := json.Unmarshal([]byte(resp.RawJSON), &mapResult); err != nil {
			return nil, llm.NewParseError(provider.Name(), resp.RawJSON, 0, err)
		}
		result = mapResult
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	if err := h.tokenUsage.RecordUsage(scope, provider.Name(), modelInfo.Name, tokenUsage); err != nil {
		h.logger.Warn("failed to record token usage", "error", err)
	}

	// Record success metrics
	h.metrics.RecordCounter("llm.structured_completions", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
		"type":     typeName,
		"status":   "success",
	})

	h.logger.Debug("structured completion with usage successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name,
		"type", typeName,
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	return &StructuredCompletionResult{
		Result:           result,
		Model:            modelInfo.Name,
		RawJSON:          resp.RawJSON,
		PromptTokens:     resp.Usage.PromptTokens,
		CompletionTokens: resp.Usage.CompletionTokens,
		TotalTokens:      resp.Usage.PromptTokens + resp.Usage.CompletionTokens,
	}, nil
}

// formatMessagesForPrompt formats LLM messages into a readable prompt string
// for observability in traces.
func formatMessagesForPrompt(messages []llm.Message) string {
	if len(messages) == 0 {
		return ""
	}

	var result string
	for i, msg := range messages {
		if i > 0 {
			result += "\n---\n"
		}
		result += fmt.Sprintf("[%s]: %s", msg.Role, msg.Content)
	}
	return result
}

// mapToJSONSchema converts a map[string]any (from JSON) to *types.JSONSchema.
// This is used when a remote agent passes a schema as JSON instead of a Go struct.
func mapToJSONSchema(m map[string]any) *types.JSONSchema {
	if m == nil {
		return nil
	}

	result := &types.JSONSchema{}

	if t, ok := m["type"].(string); ok {
		result.Type = t
	}
	if desc, ok := m["description"].(string); ok {
		result.Description = desc
	}
	if format, ok := m["format"].(string); ok {
		result.Format = format
	}
	if pattern, ok := m["pattern"].(string); ok {
		result.Pattern = pattern
	}

	// Handle required array
	if req, ok := m["required"].([]any); ok {
		result.Required = make([]string, 0, len(req))
		for _, r := range req {
			if s, ok := r.(string); ok {
				result.Required = append(result.Required, s)
			}
		}
	}

	// Handle enum array
	if enum, ok := m["enum"].([]any); ok {
		result.Enum = enum
	}

	// Handle properties (nested schemas)
	if props, ok := m["properties"].(map[string]any); ok {
		result.Properties = make(map[string]*types.JSONSchema)
		for name, prop := range props {
			if propMap, ok := prop.(map[string]any); ok {
				result.Properties[name] = mapToJSONSchema(propMap)
			}
		}
	}

	// Handle items (for array types)
	if items, ok := m["items"].(map[string]any); ok {
		result.Items = mapToJSONSchema(items)
	}

	// Note: SDK schema.JSON doesn't have AdditionalProperties field
	// if addProps, ok := m["additionalProperties"].(bool); ok {
	//	 result.AdditionalProperties = &addProps
	// }

	// Handle numeric constraints
	if min, ok := m["minimum"].(float64); ok {
		result.Minimum = &min
	}
	if max, ok := m["maximum"].(float64); ok {
		result.Maximum = &max
	}
	if minLen, ok := m["minLength"].(float64); ok {
		intVal := int(minLen)
		result.MinLength = &intVal
	}
	if maxLen, ok := m["maxLength"].(float64); ok {
		intVal := int(maxLen)
		result.MaxLength = &intVal
	}

	return result
}
