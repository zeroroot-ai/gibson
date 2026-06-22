package providers

import (
	"context"
	"os"

	einogemini "github.com/cloudwego/eino-ext/components/model/gemini"
	"google.golang.org/genai"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// GoogleProvider implements LLMProvider for Google's Gemini models.
//
// NOTE: GoogleProvider does NOT implement StructuredOutputProvider.
// Google Gemini API integration does not currently support native structured
// output through the Eino Gemini component. Attempting to use structured
// output with Google will fail with ErrStructuredOutputNotSupported at the
// SDK/manager level.
type GoogleProvider struct {
	model  *einogemini.ChatModel
	config llm.ProviderConfig
}

// NewGoogleProvider creates a new Google provider backed by the Eino Gemini component.
func NewGoogleProvider(cfg llm.ProviderConfig) (*GoogleProvider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("GOOGLE_API_KEY")
	}

	if apiKey == "" {
		return nil, llm.NewAuthError("google", nil)
	}

	genaiClient, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	einoConfig := &einogemini.Config{
		Client: genaiClient,
		Model:  cfg.DefaultModel,
	}
	m, err := einogemini.NewChatModel(context.Background(), einoConfig)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	return &GoogleProvider{
		model:  m,
		config: cfg,
	}, nil
}

// Name returns the provider name
func (p *GoogleProvider) Name() string {
	return "google"
}

// Models returns information about available models
func (p *GoogleProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
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
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)

	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	return fromEinoMessage(out, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *GoogleProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	return fromEinoMessage(out, req.Model), nil
}

// Stream sends a streaming completion request
func (p *GoogleProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)

	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("google", err)
	}

	return streamToChannel(sr, func(e error) error { return llm.TranslateError("google", e) }), nil
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
