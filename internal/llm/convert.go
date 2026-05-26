package llm

import (
	"context"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/langchaingo/llms"
)

// toSchemaMessages converts Gibson messages to langchaingo MessageContent
func toSchemaMessages(messages []Message) []llms.MessageContent {
	result := make([]llms.MessageContent, 0, len(messages))

	for _, msg := range messages {
		var msgContent llms.MessageContent

		switch msg.Role {
		case RoleSystem:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeSystem,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		case RoleUser:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeHuman,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		case RoleAssistant:
			msgContent = llms.MessageContent{
				Role: llms.ChatMessageTypeAI,
				Parts: []llms.ContentPart{
					llms.TextPart(msg.Content),
				},
			}
		case RoleTool:
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

// fromLangchainResponse extracts content and usage from langchaingo response
func fromLangchainResponse(resp *llms.ContentResponse, model string) *CompletionResponse {
	if resp == nil {
		return &CompletionResponse{
			Model: model,
			ID:    uuid.New().String(),
		}
	}

	var content string
	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		if choice.Content != "" {
			content = choice.Content
		}
	}

	usage := CompletionTokenUsage{}
	// Note: langchaingo ContentResponse doesn't have a Usage field in the current version
	// This will need to be extracted from provider-specific metadata if available

	finishReason := FinishReasonStop
	if len(resp.Choices) > 0 {
		if reason := resp.Choices[0].StopReason; reason != "" {
			switch reason {
			case "stop":
				finishReason = FinishReasonStop
			case "length", "max_tokens":
				finishReason = FinishReasonLength
			case "tool_calls", "function_call":
				finishReason = FinishReasonToolCalls
			case "content_filter":
				finishReason = FinishReasonContentFilter
			default:
				finishReason = FinishReasonStop
			}
		}
	}

	return &CompletionResponse{
		ID:    uuid.New().String(),
		Model: model,
		Message: Message{
			Role:    RoleAssistant,
			Content: content,
		},
		FinishReason: finishReason,
		Usage:        usage,
	}
}

// buildCallOptions converts Gibson completion options to langchaingo call options
func buildCallOptions(req CompletionRequest) []llms.CallOption {
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

// buildStreamingCallOptions builds call options with streaming enabled
func buildStreamingCallOptions(req CompletionRequest, streamFunc func(ctx context.Context, chunk []byte) error) []llms.CallOption {
	callOpts := buildCallOptions(req)
	callOpts = append(callOpts, llms.WithStreamingFunc(streamFunc))
	return callOpts
}
