package providers

import (
	"context"
	"strings"

	"github.com/zero-day-ai/langchaingo/llms/mistral"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/secrets"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MistralProvider wraps langchaingo's Mistral La Plateforme integration.
// Credential: cfg.APIKey or env MISTRAL_API_KEY.
type MistralProvider struct {
	client *mistral.Model
	config llm.ProviderConfig
}

// NewMistralProvider constructs a Mistral provider.
// Credentials are resolved from the broker (if available), then cfg.APIKey,
// then env-var (dev only). See resolveCredential for the full chain.
func NewMistralProvider(cfg llm.ProviderConfig) (*MistralProvider, error) {
	return newMistralProviderWithContext(context.Background(), nil, cfg)
}

// newMistralProviderWithContext constructs a Mistral provider with broker
// credential resolution. service may be nil when the broker is not available.
func newMistralProviderWithContext(ctx context.Context, service *secrets.Service, cfg llm.ProviderConfig) (*MistralProvider, error) {
	apiKey, err := resolveCredential(ctx, service, cfg, "mistral", "", "MISTRAL_API_KEY", true)
	if err != nil {
		return nil, err
	}
	opts := []mistral.Option{mistral.WithAPIKey(apiKey)}
	if cfg.DefaultModel != "" {
		opts = append(opts, mistral.WithModel(cfg.DefaultModel))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, mistral.WithEndpoint(cfg.BaseURL))
	}
	client, err := mistral.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("mistral", err)
	}
	return &MistralProvider{client: client, config: cfg}, nil
}

func (p *MistralProvider) Name() string { return "mistral" }

func (p *MistralProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	tools := []string{"chat", "streaming", "tools"}
	chat := []string{"chat", "streaming"}
	return []llm.ModelInfo{
		{Name: "mistral-large-latest", ContextWindow: 128000, MaxOutput: 8192, Features: tools},
		{Name: "mistral-medium-latest", ContextWindow: 32000, MaxOutput: 8192, Features: chat},
		{Name: "mistral-small-latest", ContextWindow: 32000, MaxOutput: 8192, Features: tools},
		{Name: "codestral-latest", ContextWindow: 32000, MaxOutput: 8192, Features: chat},
		{Name: "open-mistral-7b", ContextWindow: 32000, MaxOutput: 8192, Features: chat},
		{Name: "open-mixtral-8x7b", ContextWindow: 32000, MaxOutput: 8192, Features: chat},
		{Name: "open-mixtral-8x22b", ContextWindow: 64000, MaxOutput: 8192, Features: chat},
	}, nil
}

func (p *MistralProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateMistralError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *MistralProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptionsWithTools(req, tools)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateMistralError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *MistralProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
			chunkChan <- llm.StreamChunk{Error: translateMistralError(err)}
		}
	}()
	return chunkChan, nil
}

func (p *MistralProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "mistral client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *MistralProvider) CredentialSchema() []llm.CredentialField { return MistralCredentialSchema() }

func MistralCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "api_key", Label: "Mistral API Key", Required: true, Secret: true},
		{Key: "base_url", Label: "Endpoint (optional)", Placeholder: "https://api.mistral.ai"},
	}
}

func translateMistralError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "rate limit"):
		return llm.NewRateLimitError("mistral")
	case strings.Contains(lower, "401"), strings.Contains(lower, "403"), strings.Contains(lower, "unauthorized"):
		return llm.NewAuthError("mistral", err)
	case strings.Contains(lower, "400"), strings.Contains(lower, "invalid"):
		return llm.NewInvalidInputError("mistral", err.Error())
	default:
		return llm.TranslateError("mistral", err)
	}
}
