package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	einoclaude "github.com/cloudwego/eino-ext/components/model/claude"
	einomodel "github.com/cloudwego/eino/components/model"
	einoschema "github.com/cloudwego/eino/schema"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// AnthropicProvider implements LLMProvider for Anthropic's Claude models
// using the Eino framework.
type AnthropicProvider struct {
	model  *einoclaude.ChatModel
	config llm.ProviderConfig
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

	ctx := context.Background()
	model, err := einoclaude.NewChatModel(ctx, &einoclaude.Config{
		APIKey: apiKey,
		Model:  cfg.DefaultModel,
	})
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}

	return &AnthropicProvider{
		model:  model,
		config: cfg,
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
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *AnthropicProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// Stream sends a streaming completion request
func (p *AnthropicProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return streamToChannel(sr, req.Model, func(e error) error { return llm.TranslateError("anthropic", e) }), nil
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

// CompleteStructured performs a completion using the tool_use pattern for structured output.
// It converts the response schema to a tool definition and forces the model to use it via
// Eino's forced tool choice, guaranteeing structured JSON output matching the schema.
//
// Requirement 2.1: Anthropic provider uses tool_use pattern with single tool matching response schema
func (p *AnthropicProvider) CompleteStructured(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if req.ResponseFormat == nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", llm.ErrSchemaRequiredSentinel)
	}
	if err := req.ResponseFormat.Validate(); err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}
	if !p.SupportsStructuredOutput(req.ResponseFormat.Type) {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", llm.ErrStructuredOutputNotSupportedSentinel)
	}

	// Convert ResponseFormat schema to a ToolDef (tool_use pattern for structured output)
	toolDef := convertResponseFormatToTool(req.ResponseFormat)
	toolInfo, err := toEinoToolInfo(toolDef)
	if err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}

	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	opts = append(opts,
		einomodel.WithTools([]*einoschema.ToolInfo{toolInfo}),
		einomodel.WithToolChoice(einoschema.ToolChoiceForced, toolDef.Name),
	)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}

	if len(out.ToolCalls) == 0 {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", out.Content,
			fmt.Errorf("no tool call in response despite forced tool choice"))
	}
	rawJSON := out.ToolCalls[0].Function.Arguments
	var structuredData any
	if err := json.Unmarshal([]byte(rawJSON), &structuredData); err != nil {
		return nil, llm.NewParseError("anthropic", rawJSON, 0, err)
	}
	resp := fromEinoMessage(out, req.Model)
	resp.RawJSON = rawJSON
	resp.StructuredData = structuredData
	resp.Message.Content = rawJSON
	return resp, nil
}
