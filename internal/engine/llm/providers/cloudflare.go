// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"fmt"
	"strings"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// CloudflareProvider talks to Cloudflare Workers AI through its
// OpenAI-compatible endpoint via the Eino OpenAI ChatModel.
// Credentials: cfg.Extra["cloudflare_account_id"] + cfg.APIKey (the Cloudflare
// API token). Env fallbacks: CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN.
type CloudflareProvider struct {
	model  *einoopenai.ChatModel
	config llm.ProviderConfig
	lister *openAIListEndpoint
}

// newCloudflareProviderWithContext constructs a Cloudflare provider, resolving the credential from cfg (see resolveCredential).
func newCloudflareProviderWithContext(ctx context.Context, cfg llm.ProviderConfig) (*CloudflareProvider, error) {
	accountID, err := resolveCredential(cfg, "cloudflare", "cloudflare_account_id", true)
	if err != nil {
		return nil, err
	}
	token, err := resolveCredential(cfg, "cloudflare", "", true)
	if err != nil {
		return nil, err
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/ai/v1", accountID)
	}

	if err := validateLLMEndpoint(baseURL, cfg.AllowPrivateEndpoint); err != nil {
		return nil, err
	}

	client := guardedHTTPClient(cfg)
	m, err := einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
		APIKey:     token,
		Model:      cfg.DefaultModel,
		BaseURL:    baseURL,
		HTTPClient: client,
	})
	if err != nil {
		return nil, llm.TranslateError("cloudflare", err)
	}
	return &CloudflareProvider{
		model:  m,
		config: cfg,
		lister: &openAIListEndpoint{client: client, provider: "cloudflare", baseURL: baseURL, token: token},
	}, nil
}

func (p *CloudflareProvider) Name() string { return "cloudflare" }

// Models asks the list endpoint of the provider (GET {base}/models) for its
// models.
func (p *CloudflareProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return p.lister.Models(ctx)
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
	return streamToChannel(sr, req.Model, translateCloudflareError), nil
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
		{Key: "cloudflare_account_id", Label: "Cloudflare Account ID", Required: true, Secret: true, Placeholder: "ab12...", Type: llm.FieldPassword},
		{Key: "api_key", Label: "Cloudflare API Token", Required: true, Secret: true, Help: "API token with Workers AI permission.", Type: llm.FieldPassword},
		{Key: "base_url", Label: "Server URL (optional)", Placeholder: "https://api.cloudflare.com/client/v4/accounts/<id>/ai/v1", Type: llm.FieldURL},
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
