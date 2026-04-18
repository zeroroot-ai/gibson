package providers

import (
	"context"
	"strings"

	"github.com/tmc/langchaingo/llms/ernie"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ErnieProvider wraps langchaingo's Baidu ERNIE integration.
// ERNIE uses a two-factor credential: an API key AND a secret key.
// cfg.Extra["ernie_access_key"] + cfg.Extra["ernie_secret_key"], or env
// ERNIE_API_KEY / ERNIE_SECRET_KEY.
type ErnieProvider struct {
	client *ernie.LLM
	config llm.ProviderConfig
}

func NewErnieProvider(cfg llm.ProviderConfig) (*ErnieProvider, error) {
	apiKey, err := resolveCredential(cfg, "ernie", "ernie_access_key", "ERNIE_API_KEY", true)
	if err != nil {
		return nil, err
	}
	secretKey, err := resolveCredential(cfg, "ernie", "ernie_secret_key", "ERNIE_SECRET_KEY", true)
	if err != nil {
		return nil, err
	}
	opts := []ernie.Option{ernie.WithAKSK(apiKey, secretKey)}
	if cfg.DefaultModel != "" {
		opts = append(opts, ernie.WithModel(cfg.DefaultModel))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, ernie.WithBaseURL(cfg.BaseURL))
	}
	client, err := ernie.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("ernie", err)
	}
	return &ErnieProvider{client: client, config: cfg}, nil
}

func (p *ErnieProvider) Name() string { return "ernie" }

func (p *ErnieProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	chat := []string{"chat", "streaming"}
	return []llm.ModelInfo{
		{Name: "ernie-bot-4", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "ernie-bot-turbo", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "ernie-bot", ContextWindow: 4800, MaxOutput: 2048, Features: chat},
	}, nil
}

func (p *ErnieProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateErnieError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *ErnieProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req) // ERNIE adapter in langchaingo does not surface native tool_use
}

func (p *ErnieProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
			chunkChan <- llm.StreamChunk{Error: translateErnieError(err)}
		}
	}()
	return chunkChan, nil
}

func (p *ErnieProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "ernie client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *ErnieProvider) CredentialSchema() []llm.CredentialField { return ErnieCredentialSchema() }

func ErnieCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "ernie_access_key", Label: "Baidu ERNIE API Key", Required: true, Secret: true},
		{Key: "ernie_secret_key", Label: "Baidu ERNIE Secret Key", Required: true, Secret: true},
		{Key: "base_url", Label: "Base URL (optional)"},
	}
}

func translateErnieError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "rate limit"):
		return llm.NewRateLimitError("ernie")
	case strings.Contains(lower, "401"), strings.Contains(lower, "403"), strings.Contains(lower, "unauthorized"):
		return llm.NewAuthError("ernie", err)
	case strings.Contains(lower, "400"), strings.Contains(lower, "invalid"):
		return llm.NewInvalidInputError("ernie", err.Error())
	default:
		return llm.TranslateError("ernie", err)
	}
}
