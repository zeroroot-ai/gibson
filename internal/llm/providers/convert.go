package providers

import (
	"context"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/langchaingo/llms"
	"github.com/zeroroot-ai/sdk/schema"
)

// toSchemaMessages converts Gibson messages to langchaingo MessageContent
func toSchemaMessages(messages []llm.Message) []llms.MessageContent {
	result := make([]llms.MessageContent, 0, len(messages))

	for _, msg := range messages {
		var msgContent llms.MessageContent

		switch msg.Role {
		case llm.RoleSystem:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeSystem,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		case llm.RoleUser:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeHuman,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		case llm.RoleAssistant:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeAI,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		case llm.RoleTool:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeTool,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		default:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeHuman,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		}

		result = append(result, msgContent)
	}

	return result
}

// fromLangchainResponse converts langchaingo response to Gibson response
func fromLangchainResponse(resp *llms.ContentResponse, model string) *llm.CompletionResponse {
	if resp == nil {
		return &llm.CompletionResponse{
			Model: model,
			ID:    uuid.New().String(),
		}
	}

	var content string
	var toolCalls []llm.ToolCall
	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		if choice.Content != "" {
			content = choice.Content
		}

		// Extract tool calls from the response
		if len(choice.ToolCalls) > 0 {
			toolCalls = make([]llm.ToolCall, 0, len(choice.ToolCalls))
			for _, tc := range choice.ToolCalls {
				var name, arguments string
				if tc.FunctionCall != nil {
					name = tc.FunctionCall.Name
					arguments = tc.FunctionCall.Arguments
				}

				toolCalls = append(toolCalls, llm.ToolCall{
					ID:        tc.ID,
					Type:      tc.Type,
					Name:      name,
					Arguments: arguments,
				})
			}
		}
	}

	finishReason := llm.FinishReasonStop
	if len(resp.Choices) > 0 {
		if reason := resp.Choices[0].StopReason; reason != "" {
			switch reason {
			case "stop":
				finishReason = llm.FinishReasonStop
			case "length", "max_tokens":
				finishReason = llm.FinishReasonLength
			case "tool_calls", "function_call":
				finishReason = llm.FinishReasonToolCalls
			case "content_filter":
				finishReason = llm.FinishReasonContentFilter
			default:
				finishReason = llm.FinishReasonStop
			}
		}

		// If we have tool calls but no explicit finish reason, set it to tool_calls
		if len(toolCalls) > 0 && finishReason == llm.FinishReasonStop {
			finishReason = llm.FinishReasonToolCalls
		}
	}

	// Extract token usage from langchaingo response
	// Token usage is stored in GenerationInfo map
	tokenUsage := llm.CompletionTokenUsage{}
	if len(resp.Choices) > 0 && resp.Choices[0].GenerationInfo != nil {
		genInfo := resp.Choices[0].GenerationInfo

		// Try to extract token counts from various possible keys
		if promptTokens, ok := genInfo["prompt_tokens"].(int); ok {
			tokenUsage.PromptTokens = promptTokens
		}
		if completionTokens, ok := genInfo["completion_tokens"].(int); ok {
			tokenUsage.CompletionTokens = completionTokens
		}
		if totalTokens, ok := genInfo["total_tokens"].(int); ok {
			tokenUsage.TotalTokens = totalTokens
		}

		// Anthropic uses different key names
		if inputTokens, ok := genInfo["input_tokens"].(int); ok {
			tokenUsage.PromptTokens = inputTokens
		}
		if outputTokens, ok := genInfo["output_tokens"].(int); ok {
			tokenUsage.CompletionTokens = outputTokens
		}

		// Calculate total if not provided
		if tokenUsage.TotalTokens == 0 && (tokenUsage.PromptTokens > 0 || tokenUsage.CompletionTokens > 0) {
			tokenUsage.TotalTokens = tokenUsage.PromptTokens + tokenUsage.CompletionTokens
		}
	}

	return &llm.CompletionResponse{
		ID:    uuid.New().String(),
		Model: model,
		Message: llm.Message{
			Role:      llm.RoleAssistant,
			Content:   content,
			ToolCalls: toolCalls,
		},
		FinishReason: finishReason,
		Usage:        tokenUsage,
	}
}

// buildCallOptions converts Gibson request to langchaingo call options
func buildCallOptions(req llm.CompletionRequest) []llms.CallOption {
	callOpts := make([]llms.CallOption, 0)

	if req.Temperature > 0 {
		callOpts = append(callOpts, llms.WithTemperature(req.Temperature))
	}

	if req.MaxTokens > 0 {
		callOpts = append(callOpts, llms.WithMaxTokens(req.MaxTokens))
	}

	if req.TopP > 0 {
		callOpts = append(callOpts, llms.WithTopP(req.TopP))
	}

	if len(req.StopSequences) > 0 {
		callOpts = append(callOpts, llms.WithStopWords(req.StopSequences))
	}

	if req.Model != "" {
		callOpts = append(callOpts, llms.WithModel(req.Model))
	}

	return callOpts
}

// buildStreamingCallOptions builds call options with streaming
func buildStreamingCallOptions(req llm.CompletionRequest, streamFunc func(ctx context.Context, chunk []byte) error) []llms.CallOption {
	callOpts := buildCallOptions(req)
	callOpts = append(callOpts, llms.WithStreamingFunc(streamFunc))
	return callOpts
}

// toSchemaTools converts Gibson ToolDef to langchaingo Tool format
func toSchemaTools(tools []llm.ToolDef) []llms.Tool {
	if len(tools) == 0 {
		return nil
	}

	result := make([]llms.Tool, 0, len(tools))
	for _, tool := range tools {
		result = append(result, llms.Tool{
			Type: "function",
			Function: &llms.FunctionDefinition{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  tool.Parameters,
			},
		})
	}
	return result
}

// buildCallOptionsWithTools adds tools to call options
func buildCallOptionsWithTools(req llm.CompletionRequest, tools []llm.ToolDef) []llms.CallOption {
	callOpts := buildCallOptions(req)
	if len(tools) > 0 {
		callOpts = append(callOpts, llms.WithTools(toSchemaTools(tools)))
	}
	return callOpts
}

// buildCallOptionsWithToolChoice adds a tool with forced tool choice to call options.
// This is used for structured output where we want to force the model to use a specific tool.
func buildCallOptionsWithToolChoice(req llm.CompletionRequest, tool llm.ToolDef) []llms.CallOption {
	callOpts := buildCallOptions(req)

	// Add the single tool
	tools := []llm.ToolDef{tool}
	callOpts = append(callOpts, llms.WithTools(toSchemaTools(tools)))

	// Force the tool choice by specifying the tool explicitly
	// For Anthropic, this uses the tool_choice parameter
	toolChoice := llms.ToolChoice{
		Type: "tool",
		Function: &llms.FunctionReference{
			Name: tool.Name,
		},
	}
	callOpts = append(callOpts, llms.WithToolChoice(toolChoice))

	return callOpts
}

// convertResponseFormatToTool converts a ResponseFormat to a ToolDef for Anthropic's tool_use pattern.
// This enables structured output by having the model call a "tool" that represents the response schema.
func convertResponseFormatToTool(format *types.ResponseFormat) llm.ToolDef {
	// Convert SDK JSONSchema to internal schema.JSON
	params := convertSDKSchemaToInternal(format.Schema)

	return llm.ToolDef{
		Name:        format.Name,
		Description: "Provide a structured response matching the schema",
		Parameters:  params,
	}
}

// convertSDKSchemaToInternal converts types.JSONSchema to internal/schema.JSON.
// This bridges the type boundary for internal provider use.
func convertSDKSchemaToInternal(sdkSchema *types.JSONSchema) schema.JSON {
	if sdkSchema == nil {
		return schema.JSON{Type: "object"}
	}

	internalSchema := schema.JSON{
		Type:        sdkSchema.Type,
		Description: sdkSchema.Description,
		Required:    sdkSchema.Required,
	}

	// Convert properties if present
	if len(sdkSchema.Properties) > 0 {
		internalSchema.Properties = make(map[string]schema.JSON)
		for name, prop := range sdkSchema.Properties {
			internalSchema.Properties[name] = convertSDKSchemaFieldToInternal(prop)
		}
	}

	// Convert items if present (for arrays)
	if sdkSchema.Items != nil {
		field := convertSDKSchemaFieldToInternal(sdkSchema.Items)
		internalSchema.Items = &field
	}

	// Note: SDK schema.JSON doesn't have AdditionalProperties field

	return internalSchema
}

// convertSDKSchemaFieldToInternal converts types.JSONSchema to internal/schema.JSON.
// This is used recursively when converting nested schemas.
func convertSDKSchemaFieldToInternal(sdkField *types.JSONSchema) schema.JSON {
	if sdkField == nil {
		return schema.JSON{Type: "object"}
	}

	field := schema.JSON{
		Type:        sdkField.Type,
		Description: sdkField.Description,
		Pattern:     sdkField.Pattern,
		Format:      sdkField.Format,
		Minimum:     sdkField.Minimum,
		Maximum:     sdkField.Maximum,
		MinLength:   sdkField.MinLength,
		MaxLength:   sdkField.MaxLength,
		Required:    sdkField.Required,
	}

	// Convert enum values
	if len(sdkField.Enum) > 0 {
		field.Enum = make([]any, len(sdkField.Enum))
		copy(field.Enum, sdkField.Enum)
	}

	// Convert nested properties
	if len(sdkField.Properties) > 0 {
		field.Properties = make(map[string]schema.JSON)
		for name, prop := range sdkField.Properties {
			field.Properties[name] = convertSDKSchemaFieldToInternal(prop)
		}
	}

	// Convert items (for arrays)
	if sdkField.Items != nil {
		nestedField := convertSDKSchemaFieldToInternal(sdkField.Items)
		field.Items = &nestedField
	}

	return field
}
