package providers

import (
	"context"
	"os"

	"github.com/zero-day-ai/langchaingo/llms/googleai"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// GoogleProvider implements LLMProvider for Google's Gemini models.
//
// NOTE: GoogleProvider does NOT implement StructuredOutputProvider.
// Google Gemini API integration does not currently support native structured
// output through langchaingo. Attempting to use structured output with Google
// will fail with ErrStructuredOutputNotSupported at the SDK/manager level.
type GoogleProvider struct {
	client *googleai.GoogleAI
	config llm.ProviderConfig
}

// NewGoogleProvider creates a new Google provider
func NewGoogleProvider(cfg llm.ProviderConfig) (*GoogleProvider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("GOOGLE_API_KEY")
	}

	if apiKey == "" {
		return nil, llm.NewAuthError("google", nil)
	}

	opts := []googleai.Option{
		googleai.WithAPIKey(apiKey),
	}

	if cfg.DefaultModel != "" {
		opts = append(opts, googleai.WithDefaultModel(cfg.DefaultModel))
	}

	client, err := googleai.New(context.Background(), opts...)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	return &GoogleProvider{
		client: client,
		config: cfg,
	}, nil
}

// Name returns the provider name
func (p *GoogleProvider) Name() string {
	return "google"
}

// Models returns information about available models
func (p *GoogleProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	models := []llm.ModelInfo{
		{
			Name:          "gemini-1.5-pro",
			ContextWindow: 1048576,
			MaxOutput:     8192,
			Features:      []string{"chat", "streaming", "tools", "vision"},
		},
		{
			Name:          "gemini-1.5-flash",
			ContextWindow: 1048576,
			MaxOutput:     8192,
			Features:      []string{"chat", "streaming", "tools", "vision"},
		},
		{
			Name:          "gemini-pro",
			ContextWindow: 32768,
			MaxOutput:     8192,
			Features:      []string{"chat", "streaming", "tools"},
		},
	}
	return models, nil
}

// Complete sends a completion request
func (p *GoogleProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptions(req)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *GoogleProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptionsWithTools(req, tools)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// Stream sends a streaming completion request
func (p *GoogleProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
				Error: llm.TranslateError("google", err),
			}
		}
	}()

	return chunkChan, nil
}

// Health checks the provider health
func (p *GoogleProvider) Health(ctx context.Context) types.HealthStatus {
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
