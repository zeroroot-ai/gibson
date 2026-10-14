// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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
	lister *cloudflareListEndpoint
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
		lister: &cloudflareListEndpoint{client: client, listURL: cloudflareModelsURL(baseURL), token: token},
	}, nil
}

func (p *CloudflareProvider) Name() string { return "cloudflare" }

// Models asks the Cloudflare model search endpoint (see
// https://developers.cloudflare.com/api/resources/ai/subresources/models/) for
// the text generation models. The OpenAI compatibility route has no list call.
func (p *CloudflareProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return p.lister.Models(ctx)
}

// cloudflareModelsURL turns the compatibility base URL
// (.../accounts/{id}/ai/v1) into the search URL (.../accounts/{id}/ai/models/search).
func cloudflareModelsURL(baseURL string) string {
	return strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/v1") + "/models/search"
}

// cloudflareListEndpoint lists Workers AI models with
// GET /accounts/{id}/ai/models/search?task=Text Generation. The response is the
// Cloudflare envelope {"result":[{"name","task":{"name"}}],"result_info":{...}}.
type cloudflareListEndpoint struct {
	client  *http.Client
	listURL string
	token   string
	cache   modelCache
}

// Models returns the text generation models and follows the result pages.
func (e *cloudflareListEndpoint) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return e.cache.get(ctx, "cloudflare", func(ctx context.Context) ([]llm.ModelInfo, error) {
		header := http.Header{}
		header.Set("Authorization", "Bearer "+e.token)
		var models []llm.ModelInfo
		for pageNo := 1; pageNo <= maxModelListPages; pageNo++ {
			q := url.Values{"task": {"Text Generation"}, "per_page": {"100"}, "page": {strconv.Itoa(pageNo)}}
			var page struct {
				Result []struct {
					Name string `json:"name"`
				} `json:"result"`
				ResultInfo struct {
					Page       int `json:"page"`
					PerPage    int `json:"per_page"`
					TotalCount int `json:"total_count"`
				} `json:"result_info"`
			}
			if err := getJSON(ctx, e.client, "cloudflare", e.listURL+"?"+q.Encode(), header, &page); err != nil {
				return nil, err
			}
			for _, m := range page.Result {
				if m.Name != "" {
					models = append(models, llm.ModelInfo{Name: m.Name})
				}
			}
			if len(page.Result) == 0 || pageNo*100 >= page.ResultInfo.TotalCount {
				return models, nil
			}
		}
		return models, nil
	})
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

// DefaultModel returns the default model saved for this provider, or "".
func (p *CloudflareProvider) DefaultModel() string { return p.config.DefaultModel }
