package providers

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/langchaingo/llms/ollama"
)

// OllamaProvider implements LLMProvider for local Ollama models.
//
// NOTE: OllamaProvider does NOT implement StructuredOutputProvider.
// Ollama does not have native structured output support (no JSON mode).
// Attempting to use structured output with Ollama will fail with
// ErrStructuredOutputNotSupported at the SDK/manager level.
type OllamaProvider struct {
	client *ollama.LLM
	config llm.ProviderConfig
}

// NewOllamaProvider creates a new Ollama provider
func NewOllamaProvider(cfg llm.ProviderConfig) (*OllamaProvider, error) {
	serverURL := cfg.BaseURL
	if serverURL == "" {
		serverURL = "http://localhost:11434"
	}

	opts := []ollama.Option{
		ollama.WithServerURL(serverURL),
	}

	if cfg.DefaultModel != "" {
		opts = append(opts, ollama.WithModel(cfg.DefaultModel))
	}

	client, err := ollama.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return &OllamaProvider{
		client: client,
		config: cfg,
	}, nil
}

// Name returns the provider name
func (p *OllamaProvider) Name() string {
	return "ollama"
}

// Models returns information about available models
func (p *OllamaProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
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
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptions(req)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *OllamaProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptionsWithTools(req, tools)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// Stream sends a streaming completion request
func (p *OllamaProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
				Error: llm.TranslateError("ollama", err),
			}
		}
	}()

	return chunkChan, nil
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
