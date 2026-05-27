package providers

import (
	"context"
	"fmt"
	"strings"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// CloudflareProvider talks to Cloudflare Workers AI through its
// OpenAI-compatible endpoint via the Eino OpenAI ChatModel.
// Credentials: cfg.Extra["cloudflare_account_id"] + cfg.APIKey (the Cloudflare
// API token). Env fallbacks: CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN.
type CloudflareProvider struct {
	model  *einoopenai.ChatModel
	config llm.ProviderConfig
}

// NewCloudflareProvider constructs a Cloudflare Workers AI provider.
// Credentials are resolved from the broker (if service is non-nil), then
// cfg.Extra, then env-var (dev only). See resolveCredential for the full chain.
func NewCloudflareProvider(cfg llm.ProviderConfig) (*CloudflareProvider, error) {
	return newCloudflareProviderWithContext(context.Background(), nil, cfg)
}

// newCloudflareProviderWithContext constructs a Cloudflare provider with broker
// credential resolution. service may be nil when the broker is not available.
func newCloudflareProviderWithContext(ctx context.Context, service *secrets.Service, cfg llm.ProviderConfig) (*CloudflareProvider, error) {
	accountID, err := resolveCredential(ctx, service, cfg, "cloudflare", "cloudflare_account_id", "CLOUDFLARE_ACCOUNT_ID", true)
	if err != nil {
		return nil, err
	}
	token, err := resolveCredential(ctx, service, cfg, "cloudflare", "", "CLOUDFLARE_API_TOKEN", true)
	if err != nil {
		return nil, err
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/ai/v1", accountID)
	}

	m, err := einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
		APIKey:  token,
		Model:   cfg.DefaultModel,
		BaseURL: baseURL,
	})
	if err != nil {
		return nil, llm.TranslateError("cloudflare", err)
	}
	return &CloudflareProvider{model: m, config: cfg}, nil
}

func (p *CloudflareProvider) Name() string { return "cloudflare" }

func (p *CloudflareProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	chat := []string{"chat", "streaming"}
	return []llm.ModelInfo{
		{Name: "@cf/meta/llama-3.1-8b-instruct", ContextWindow: 128000, MaxOutput: 4096, Features: chat},
		{Name: "@cf/meta/llama-3-8b-instruct", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "@cf/meta/llama-2-7b-chat-int8", ContextWindow: 4096, MaxOutput: 2048, Features: chat},
		{Name: "@cf/mistral/mistral-7b-instruct-v0.1", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "@cf/google/gemma-7b-it", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "@cf/qwen/qwen1.5-14b-chat-awq", ContextWindow: 32768, MaxOutput: 2048, Features: chat},
	}, nil
}

func (p *CloudflareProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, translateCloudflareError(err)
	}
	return fromEinoMessage(out, req.Model), nil
}

func (p *CloudflareProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, translateCloudflareError(err)
	}
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, translateCloudflareError(err)
	}
	return fromEinoMessage(out, req.Model), nil
}

func (p *CloudflareProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, translateCloudflareError(err)
	}
	return streamToChannel(sr, translateCloudflareError), nil
}

func (p *CloudflareProvider) Health(_ context.Context) types.HealthStatus {
	if p.model == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "cloudflare client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *CloudflareProvider) CredentialSchema() []llm.CredentialField {
	return CloudflareCredentialSchema()
}

func CloudflareCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "cloudflare_account_id", Label: "Cloudflare Account ID", Required: true, Secret: true, Placeholder: "ab12..."},
		{Key: "api_key", Label: "Cloudflare API Token", Required: true, Secret: true, Help: "API token with Workers AI permission."},
		{Key: "base_url", Label: "Server URL (optional)", Placeholder: "https://api.cloudflare.com/client/v4/accounts/<id>/ai/v1"},
	}
}

func translateCloudflareError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "too many requests"), strings.Contains(lower, "rate limit"):
		return llm.NewRateLimitError("cloudflare")
	case strings.Contains(lower, "401"), strings.Contains(lower, "403"), strings.Contains(lower, "unauthorized"), strings.Contains(lower, "forbidden"):
		return llm.NewAuthError("cloudflare", err)
	case strings.Contains(lower, "400"), strings.Contains(lower, "invalid"):
		return llm.NewInvalidInputError("cloudflare", err.Error())
	default:
		return llm.TranslateError("cloudflare", err)
	}
}
