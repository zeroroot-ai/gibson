package providers

import (
	"context"
	"strings"

	"github.com/tmc/langchaingo/llms/cohere"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/secrets"
	"github.com/zero-day-ai/gibson/internal/types"
)

// CohereProvider wraps langchaingo's Cohere integration.
// Credential: cfg.APIKey or env COHERE_API_KEY.
type CohereProvider struct {
	client *cohere.LLM
	config llm.ProviderConfig
}

// NewCohereProvider constructs a Cohere provider.
// Credentials are resolved from the broker (if available), then cfg.APIKey,
// then env-var (dev only). See resolveCredential for the full chain.
func NewCohereProvider(cfg llm.ProviderConfig) (*CohereProvider, error) {
	return newCohereProviderWithContext(context.Background(), nil, cfg)
}

// newCohereProviderWithContext constructs a Cohere provider with broker
// credential resolution. service may be nil when the broker is not available.
func newCohereProviderWithContext(ctx context.Context, service *secrets.Service, cfg llm.ProviderConfig) (*CohereProvider, error) {
	token, err := resolveCredential(ctx, service, cfg, "cohere", "", "COHERE_API_KEY", true)
	if err != nil {
		return nil, err
	}
	opts := []cohere.Option{cohere.WithToken(token)}
	if cfg.DefaultModel != "" {
		opts = append(opts, cohere.WithModel(cfg.DefaultModel))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, cohere.WithBaseURL(cfg.BaseURL))
	}
	client, err := cohere.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("cohere", err)
	}
	return &CohereProvider{client: client, config: cfg}, nil
}

func (p *CohereProvider) Name() string { return "cohere" }

func (p *CohereProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	chat := []string{"chat", "streaming"}
	return []llm.ModelInfo{
		{Name: "command-r-plus", ContextWindow: 128000, MaxOutput: 4096, Features: chat},
		{Name: "command-r", ContextWindow: 128000, MaxOutput: 4096, Features: chat},
		{Name: "command", ContextWindow: 4096, MaxOutput: 4096, Features: chat},
		{Name: "command-light", ContextWindow: 4096, MaxOutput: 4096, Features: chat},
	}, nil
}

func (p *CohereProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateCohereError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *CohereProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	// langchaingo's Cohere adapter does not currently bridge Cohere's native
	// tool_use API; fall back to text completion.
	return p.Complete(ctx, req)
}

func (p *CohereProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
			chunkChan <- llm.StreamChunk{Error: translateCohereError(err)}
		}
	}()
	return chunkChan, nil
}

func (p *CohereProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "cohere client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *CohereProvider) CredentialSchema() []llm.CredentialField { return CohereCredentialSchema() }

func CohereCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "api_key", Label: "Cohere API Key", Required: true, Secret: true},
		{Key: "base_url", Label: "Base URL (optional)", Placeholder: "https://api.cohere.ai"},
	}
}

func translateCohereError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "rate limit"):
		return llm.NewRateLimitError("cohere")
	case strings.Contains(lower, "401"), strings.Contains(lower, "403"), strings.Contains(lower, "unauthorized"):
		return llm.NewAuthError("cohere", err)
	case strings.Contains(lower, "400"), strings.Contains(lower, "invalid"):
		return llm.NewInvalidInputError("cohere", err.Error())
	default:
		return llm.TranslateError("cohere", err)
	}
}
