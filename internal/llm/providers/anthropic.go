package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tmc/langchaingo/llms/anthropic"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// AnthropicProvider implements LLMProvider for Anthropic's Claude models
type AnthropicProvider struct {
	client       *anthropic.LLM
	directClient *AnthropicDirectClient
	config       llm.ProviderConfig
}

// NewAnthropicProvider creates a new Anthropic provider
func NewAnthropicProvider(cfg llm.ProviderConfig) (*AnthropicProvider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	if apiKey == "" {
		return nil, llm.NewAuthError("anthropic", nil)
	}

	opts := []anthropic.Option{
		anthropic.WithToken(apiKey),
	}

	if cfg.DefaultModel != "" {
		opts = append(opts, anthropic.WithModel(cfg.DefaultModel))
	}

	client, err := anthropic.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}

	return &AnthropicProvider{
		client:       client,
		directClient: NewAnthropicDirectClient(apiKey),
		config:       cfg,
	}, nil
}

// Name returns the provider name
func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

// Models returns information about available models
func (p *AnthropicProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	models := []llm.ModelInfo{
		{
			Name:          "claude-sonnet-4-5-20250929",
			ContextWindow: 200000,
			MaxOutput:     8192,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
		{
			Name:          "claude-opus-4-20250514",
			ContextWindow: 200000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
		{
			Name:          "claude-sonnet-4-20250514",
			ContextWindow: 200000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
		{
			Name:          "claude-3-haiku-20240307",
			ContextWindow: 200000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
	}
	return models, nil
}

// Complete sends a completion request
func (p *AnthropicProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptions(req)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *AnthropicProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptionsWithTools(req, tools)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// Stream sends a streaming completion request
func (p *AnthropicProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	chunkChan := make(chan llm.StreamChunk, 10)

	messages := toSchemaMessages(req.Messages)
	callOpts := buildStreamingCallOptions(req, func(ctx context.Context, chunk []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunkChan <- llm.StreamChunk{
			Delta: llm.StreamDelta{
				Content: string(chunk),
			},
		}:
			return nil
		}
	})

	go func() {
		defer close(chunkChan)
		_, err := p.client.GenerateContent(ctx, messages, callOpts...)
		if err != nil {
			chunkChan <- llm.StreamChunk{
				Error: llm.TranslateError("anthropic", err),
			}
		}
	}()

	return chunkChan, nil
}

// Health checks the provider health
func (p *AnthropicProvider) Health(ctx context.Context) types.HealthStatus {
	// Try a simple API call to check health
	req := llm.CompletionRequest{
		Model: p.config.DefaultModel,
		Messages: []llm.Message{
			llm.NewUserMessage("test"),
		},
		MaxTokens: 1,
	}

	_, err := p.Complete(ctx, req)
	if err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}

	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// SupportsStructuredOutput returns true for json_schema format.
// Anthropic uses the tool_use pattern which effectively supports json_schema.
func (p *AnthropicProvider) SupportsStructuredOutput(format types.ResponseFormatType) bool {
	return format == types.ResponseFormatJSONSchema
}

// CompleteStructured performs a completion using tool_use pattern for structured output.
// This method converts the response schema to a tool definition and forces the model
// to use it, guaranteeing structured JSON output matching the schema.
//
// This uses the direct Anthropic HTTP client instead of langchaingo because
// langchaingo v0.1.10's Anthropic provider does not support tool_choice.
//
// Requirement 2.1: Anthropic provider uses tool_use pattern with single tool matching response schema
func (p *AnthropicProvider) CompleteStructured(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	// Validate that ResponseFormat is provided
	if req.ResponseFormat == nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", llm.ErrSchemaRequiredSentinel)
	}

	// Validate the response format
	if err := req.ResponseFormat.Validate(); err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}

	// Check if format is supported
	if !p.SupportsStructuredOutput(req.ResponseFormat.Type) {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "",
			llm.ErrStructuredOutputNotSupportedSentinel)
	}

	// Convert response schema to a tool definition
	// The tool represents the structured output format we want
	tool := convertResponseFormatToTool(req.ResponseFormat)

	// Use the direct Anthropic client which properly supports tool_choice
	// This bypasses langchaingo which lacks tool_choice support
	resp, err := p.directClient.CompleteWithForcedTool(ctx, req, tool)
	if err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}

	// Extract tool call arguments as the structured response
	if len(resp.Message.ToolCalls) == 0 {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", resp.Message.Content,
			fmt.Errorf("no tool call in response despite forced tool choice"))
	}

	// The tool call arguments ARE the structured response
	toolCall := resp.Message.ToolCalls[0]
	rawJSON := toolCall.Arguments
	resp.RawJSON = rawJSON

	// Parse to verify it's valid JSON
	var structuredData any
	if err := json.Unmarshal([]byte(rawJSON), &structuredData); err != nil {
		return nil, llm.NewParseError("anthropic", rawJSON, 0, err)
	}
	resp.StructuredData = structuredData

	// Update the message content to contain the JSON
	// This provides a consistent interface with other providers
	resp.Message.Content = rawJSON

	return resp, nil
}
