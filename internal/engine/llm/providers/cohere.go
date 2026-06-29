package providers

import (
	"context"
	"strings"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
)

// CohereProvider talks to Cohere through its OpenAI-compatibility endpoint
// (https://api.cohere.com/compatibility/v1) via the Eino OpenAI ChatModel.
// Credential: cfg.APIKey or env COHERE_API_KEY.
type CohereProvider struct {
	model  *einoopenai.ChatModel
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

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.cohere.com/compatibility/v1"
	}

	m, err := einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
		APIKey:  token,
		Model:   cfg.DefaultModel,
		BaseURL: baseURL,
	})
	if err != nil {
		return nil, llm.TranslateError("cohere", err)
	}
	return &CohereProvider{model: m, config: cfg}, nil
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
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, translateCohereError(err)
	}
	return fromEinoMessage(out, req.Model), nil
}

func (p *CohereProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	// Cohere compatibility endpoint does not bridge native tool_use API.
	return p.Complete(ctx, req)
}

func (p *CohereProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, translateCohereError(err)
	}
	return streamToChannel(sr, req.Model, translateCohereError), nil
}

func (p *CohereProvider) Health(_ context.Context) types.HealthStatus {
	if p.model == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "cohere client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *CohereProvider) CredentialSchema() []llm.CredentialField { return CohereCredentialSchema() }

func CohereCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "api_key", Label: "Cohere API Key", Required: true, Secret: true},
		{Key: "base_url", Label: "Base URL (optional)", Placeholder: "https://api.cohere.com/compatibility/v1"},
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
