package providers

import (
	"context"
	"strings"

	wx "github.com/IBM/watsonx-go/pkg/models"
	"github.com/tmc/langchaingo/llms/watsonx"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// WatsonXProvider wraps langchaingo's IBM WatsonX integration.
// Credentials: cfg.APIKey + cfg.Extra["watsonx_project_id"] (both required).
// Env fallback: WATSONX_API_KEY / WATSONX_PROJECT_ID.
type WatsonXProvider struct {
	client *watsonx.LLM
	config llm.ProviderConfig
}

func NewWatsonXProvider(cfg llm.ProviderConfig) (*WatsonXProvider, error) {
	apiKey, err := resolveCredential(cfg, "watsonx", "", "WATSONX_API_KEY", true)
	if err != nil {
		return nil, err
	}
	projectID, err := resolveCredential(cfg, "watsonx", "watsonx_project_id", "WATSONX_PROJECT_ID", true)
	if err != nil {
		return nil, err
	}

	modelID := cfg.DefaultModel
	if modelID == "" {
		modelID = "ibm/granite-13b-chat-v2"
	}

	opts := []wx.ClientOption{
		wx.WithWatsonxAPIKey(wx.WatsonxAPIKey(apiKey)),
		wx.WithWatsonxProjectID(wx.WatsonxProjectID(projectID)),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, wx.WithURL(cfg.BaseURL))
	}

	client, err := watsonx.New(modelID, opts...)
	if err != nil {
		return nil, llm.TranslateError("watsonx", err)
	}
	return &WatsonXProvider{client: client, config: cfg}, nil
}

func (p *WatsonXProvider) Name() string { return "watsonx" }

func (p *WatsonXProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	chat := []string{"chat", "streaming"}
	return []llm.ModelInfo{
		{Name: "ibm/granite-13b-chat-v2", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "ibm/granite-20b-multilingual", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "meta-llama/llama-3-70b-instruct", ContextWindow: 8192, MaxOutput: 4096, Features: chat},
		{Name: "meta-llama/llama-3-8b-instruct", ContextWindow: 8192, MaxOutput: 4096, Features: chat},
		{Name: "mistralai/mixtral-8x7b-instruct-v01", ContextWindow: 32768, MaxOutput: 4096, Features: chat},
	}, nil
}

func (p *WatsonXProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateWatsonXError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *WatsonXProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req) // WatsonX adapter does not bridge structured tool_use
}

func (p *WatsonXProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
			chunkChan <- llm.StreamChunk{Error: translateWatsonXError(err)}
		}
	}()
	return chunkChan, nil
}

func (p *WatsonXProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "watsonx client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *WatsonXProvider) CredentialSchema() []llm.CredentialField { return WatsonXCredentialSchema() }

func WatsonXCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "api_key", Label: "IBM Cloud API Key", Required: true, Secret: true},
		{Key: "watsonx_project_id", Label: "WatsonX Project ID", Required: true, Secret: true},
		{Key: "base_url", Label: "Region URL (optional)", Placeholder: "https://us-south.ml.cloud.ibm.com", Help: "Region-specific endpoint; defaults to us-south."},
	}
}

func translateWatsonXError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "rate limit"):
		return llm.NewRateLimitError("watsonx")
	case strings.Contains(lower, "401"), strings.Contains(lower, "403"), strings.Contains(lower, "unauthorized"):
		return llm.NewAuthError("watsonx", err)
	case strings.Contains(lower, "400"), strings.Contains(lower, "invalid"):
		return llm.NewInvalidInputError("watsonx", err.Error())
	default:
		return llm.TranslateError("watsonx", err)
	}
}
