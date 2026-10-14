// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// CohereProvider talks to Cohere through its OpenAI-compatibility endpoint
// (https://api.cohere.com/compatibility/v1) via the Eino OpenAI ChatModel.
// Credential: cfg.APIKey or env COHERE_API_KEY.
type CohereProvider struct {
	model  *einoopenai.ChatModel
	config llm.ProviderConfig
	lister *cohereListEndpoint
}

// newCohereProviderWithContext constructs a Cohere provider, resolving the credential from cfg (see resolveCredential).
func newCohereProviderWithContext(ctx context.Context, cfg llm.ProviderConfig) (*CohereProvider, error) {
	token, err := resolveCredential(cfg, "cohere", "", true)
	if err != nil {
		return nil, err
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.cohere.com/compatibility/v1"
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
		return nil, llm.TranslateError("cohere", err)
	}
	return &CohereProvider{
		model:  m,
		config: cfg,
		lister: &cohereListEndpoint{client: client, listURL: cohereModelsURL(baseURL), token: token},
	}, nil
}

func (p *CohereProvider) Name() string { return "cohere" }

// Models asks the native Cohere list endpoint (see
// https://docs.cohere.com/reference/list-models) for the chat models of the
// account. The OpenAI compatibility route has no list call.
func (p *CohereProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return p.lister.Models(ctx)
}

// cohereModelsURL returns the native list URL for a compatibility base URL:
// GET {origin}/v1/models. The compatibility path (/compatibility/v1) is dropped.
func cohereModelsURL(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return strings.TrimRight(baseURL, "/") + "/v1/models"
	}
	return u.Scheme + "://" + u.Host + "/v1/models"
}

// cohereListEndpoint lists Cohere models with GET /v1/models. The response is
// {"models":[{"name","context_length","endpoints"}],"next_page_token"}.
type cohereListEndpoint struct {
	client  *http.Client
	listURL string
	token   string
	cache   modelCache
}

// Models returns the chat models that Cohere reports and follows next_page_token.
func (e *cohereListEndpoint) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return e.cache.get(ctx, "cohere", func(ctx context.Context) ([]llm.ModelInfo, error) {
		header := http.Header{}
		header.Set("Authorization", "Bearer "+e.token)
		var models []llm.ModelInfo
		pageToken := ""
		for range maxModelListPages {
			q := url.Values{"page_size": {"1000"}, "endpoint": {"chat"}}
			if pageToken != "" {
				q.Set("page_token", pageToken)
			}
			var page struct {
				Models []struct {
					Name          string  `json:"name"`
					ContextLength float64 `json:"context_length"`
				} `json:"models"`
				NextPageToken string `json:"next_page_token"`
			}
			if err := getJSON(ctx, e.client, "cohere", e.listURL+"?"+q.Encode(), header, &page); err != nil {
				return nil, err
			}
			for _, m := range page.Models {
				if m.Name != "" {
					models = append(models, llm.ModelInfo{Name: m.Name, ContextWindow: int(m.ContextLength)})
				}
			}
			if page.NextPageToken == "" || page.NextPageToken == pageToken {
				return models, nil
			}
			pageToken = page.NextPageToken
		}
		return models, nil
	})
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
		{Key: "api_key", Label: "Cohere API Key", Required: true, Secret: true, Type: llm.FieldPassword},
		{Key: "base_url", Label: "Base URL (optional)", Placeholder: "https://api.cohere.com/compatibility/v1", Type: llm.FieldURL},
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

// DefaultModel returns the default model saved for this provider, or "".
func (p *CohereProvider) DefaultModel() string { return p.config.DefaultModel }
