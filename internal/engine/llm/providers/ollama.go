package providers

import (
	"context"

	einoollama "github.com/cloudwego/eino-ext/components/model/ollama"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// OllamaProvider implements LLMProvider for local Ollama models.
//
// NOTE: OllamaProvider does NOT implement StructuredOutputProvider.
// Ollama does not have native structured output support (no JSON mode).
// Attempting to use structured output with Ollama will fail with
// ErrStructuredOutputNotSupported at the SDK/manager level.
type OllamaProvider struct {
	model  *einoollama.ChatModel
	config llm.ProviderConfig
}

// NewOllamaProvider creates a new Ollama provider backed by the Eino Ollama component.
func NewOllamaProvider(cfg llm.ProviderConfig) (*OllamaProvider, error) {
	serverURL := cfg.BaseURL
	if serverURL == "" {
		serverURL = "http://localhost:11434"
	}

	einoConfig := &einoollama.ChatModelConfig{
		BaseURL: serverURL,
		Model:   cfg.DefaultModel,
	}
	m, err := einoollama.NewChatModel(context.Background(), einoConfig)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return &OllamaProvider{
		model:  m,
		config: cfg,
	}, nil
}

// Name returns the provider name
func (p *OllamaProvider) Name() string {
	return "ollama"
}

// Models returns information about available models
func (p *OllamaProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	// Return default local models - actual models would need to be queried from Ollama
	models := []llm.ModelInfo{
		{
			Name:          "llama2",
			ContextWindow: 4096,
			MaxOutput:     2048,
			Features:      []string{"chat", "streaming"},
		},
	}
	return models, nil
}

// Complete sends a completion request
func (p *OllamaProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)

	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return fromEinoMessage(out, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *OllamaProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return fromEinoMessage(out, req.Model), nil
}

// Stream sends a streaming completion request
func (p *OllamaProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)

	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return streamToChannel(sr, req.Model, func(e error) error { return llm.TranslateError("ollama", e) }), nil
}

// Health checks the provider health
func (p *OllamaProvider) Health(ctx context.Context) types.HealthStatus {
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
