package providers

import (
	"context"
	"net/http"
	"strings"

	"github.com/tmc/langchaingo/llms/cloudflare"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/secrets"
	"github.com/zero-day-ai/gibson/internal/types"
)

// CloudflareProvider wraps langchaingo's Cloudflare Workers AI integration.
// Credentials: cfg.Extra["cloudflare_account_id"] + cfg.APIKey (the Cloudflare
// API token). Env fallbacks: CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN.
type CloudflareProvider struct {
	client *cloudflare.LLM
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

	opts := []cloudflare.Option{
		cloudflare.WithAccountID(accountID),
		cloudflare.WithToken(token),
		cloudflare.WithHTTPClient(http.DefaultClient),
	}
	if cfg.DefaultModel != "" {
		opts = append(opts, cloudflare.WithModel(cfg.DefaultModel))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, cloudflare.WithServerURL(cfg.BaseURL))
	}

	client, err := cloudflare.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("cloudflare", err)
	}
	return &CloudflareProvider{client: client, config: cfg}, nil
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
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateCloudflareError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *CloudflareProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	// Cloudflare Workers AI does not currently support structured tool calls
	// via langchaingo. Fall back to plain Complete.
	return p.Complete(ctx, req)
}

func (p *CloudflareProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
			chunkChan <- llm.StreamChunk{Error: translateCloudflareError(err)}
		}
	}()
	return chunkChan, nil
}

func (p *CloudflareProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
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
		{Key: "base_url", Label: "Server URL (optional)", Placeholder: "https://api.cloudflare.com/client/v4"},
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
