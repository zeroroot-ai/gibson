package providers

import (
	"context"
	"strings"

	"github.com/tmc/langchaingo/llms/maritaca"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MaritacaProvider wraps langchaingo's Maritaca AI integration.
// Credential: cfg.APIKey or env MARITACA_API_KEY.
type MaritacaProvider struct {
	client *maritaca.LLM
	config llm.ProviderConfig
}

func NewMaritacaProvider(cfg llm.ProviderConfig) (*MaritacaProvider, error) {
	token, err := resolveCredential(cfg, "maritaca", "", "MARITACA_API_KEY", true)
	if err != nil {
		return nil, err
	}
	opts := []maritaca.Option{maritaca.WithToken(token)}
	if cfg.DefaultModel != "" {
		opts = append(opts, maritaca.WithModel(cfg.DefaultModel))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, maritaca.WithServerURL(cfg.BaseURL))
	}
	client, err := maritaca.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("maritaca", err)
	}
	return &MaritacaProvider{client: client, config: cfg}, nil
}

func (p *MaritacaProvider) Name() string { return "maritaca" }

func (p *MaritacaProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	chat := []string{"chat", "streaming"}
	return []llm.ModelInfo{
		{Name: "sabia-3", ContextWindow: 32000, MaxOutput: 4096, Features: chat},
		{Name: "sabia-2-medium", ContextWindow: 32000, MaxOutput: 4096, Features: chat},
		{Name: "sabia-2-small", ContextWindow: 32000, MaxOutput: 4096, Features: chat},
	}, nil
}

func (p *MaritacaProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateMaritacaError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *MaritacaProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}

func (p *MaritacaProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	chunkChan := make(chan llm.StreamChunk, 10)
	messages := toSchemaMessages(req.Messages)
	opts := buildStreamingCallOptions(req, func(ctx context.Context, chunk []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunkChan <- llm.StreamChunk{Delta: llm.StreamDelta{Content: string(chunk)}}:
			return nil
		}
	})
	go func() {
		defer close(chunkChan)
		_, err := p.client.GenerateContent(ctx, messages, opts...)
		if err != nil {
			chunkChan <- llm.StreamChunk{Error: translateMaritacaError(err)}
		}
	}()
	return chunkChan, nil
}

func (p *MaritacaProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "maritaca client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *MaritacaProvider) CredentialSchema() []llm.CredentialField {
	return MaritacaCredentialSchema()
}

func MaritacaCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "api_key", Label: "Maritaca API Key", Required: true, Secret: true},
		{Key: "base_url", Label: "Server URL (optional)"},
	}
}

func translateMaritacaError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "rate limit"):
		return llm.NewRateLimitError("maritaca")
	case strings.Contains(lower, "401"), strings.Contains(lower, "403"), strings.Contains(lower, "unauthorized"):
		return llm.NewAuthError("maritaca", err)
	case strings.Contains(lower, "400"), strings.Contains(lower, "invalid"):
		return llm.NewInvalidInputError("maritaca", err.Error())
	default:
		return llm.TranslateError("maritaca", err)
	}
}
