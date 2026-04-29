package providers

import (
	"context"
	"strings"

	"github.com/tmc/langchaingo/llms/huggingface"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/secrets"
	"github.com/zero-day-ai/gibson/internal/types"
)

// HuggingFaceProvider wraps langchaingo's HuggingFace Inference API integration.
// Credential: cfg.APIKey or env HUGGINGFACE_API_TOKEN.
// Optional self-host: cfg.BaseURL points at a Text Generation Inference endpoint.
type HuggingFaceProvider struct {
	client *huggingface.LLM
	config llm.ProviderConfig
}

// NewHuggingFaceProvider constructs a HuggingFace Inference API provider.
// Credentials are resolved from the broker (if available), then cfg.APIKey,
// then env-var (dev only). See resolveCredential for the full chain.
func NewHuggingFaceProvider(cfg llm.ProviderConfig) (*HuggingFaceProvider, error) {
	return newHuggingFaceProviderWithContext(context.Background(), nil, cfg)
}

// newHuggingFaceProviderWithContext constructs a HuggingFace provider with broker
// credential resolution. service may be nil when the broker is not available.
func newHuggingFaceProviderWithContext(ctx context.Context, service *secrets.Service, cfg llm.ProviderConfig) (*HuggingFaceProvider, error) {
	token, err := resolveCredential(ctx, service, cfg, "huggingface", "", "HUGGINGFACE_API_TOKEN", true)
	if err != nil {
		return nil, err
	}
	opts := []huggingface.Option{huggingface.WithToken(token)}
	if cfg.DefaultModel != "" {
		opts = append(opts, huggingface.WithModel(cfg.DefaultModel))
	}
	if cfg.BaseURL != "" {
		opts = append(opts, huggingface.WithURL(cfg.BaseURL))
	}
	client, err := huggingface.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("huggingface", err)
	}
	return &HuggingFaceProvider{client: client, config: cfg}, nil
}

func (p *HuggingFaceProvider) Name() string { return "huggingface" }

func (p *HuggingFaceProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	chat := []string{"chat", "streaming"}
	return []llm.ModelInfo{
		{Name: "meta-llama/Llama-3.1-70B-Instruct", ContextWindow: 128000, MaxOutput: 4096, Features: chat},
		{Name: "meta-llama/Llama-3.1-8B-Instruct", ContextWindow: 128000, MaxOutput: 4096, Features: chat},
		{Name: "meta-llama/Llama-3-70B-Instruct", ContextWindow: 8192, MaxOutput: 4096, Features: chat},
		{Name: "mistralai/Mixtral-8x7B-Instruct-v0.1", ContextWindow: 32768, MaxOutput: 4096, Features: chat},
		{Name: "HuggingFaceH4/zephyr-7b-beta", ContextWindow: 32768, MaxOutput: 4096, Features: chat},
		{Name: "google/gemma-2-9b-it", ContextWindow: 8192, MaxOutput: 4096, Features: chat},
	}, nil
}

func (p *HuggingFaceProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateHuggingFaceError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *HuggingFaceProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req) // HF inference API does not support structured tool_use
}

func (p *HuggingFaceProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
			chunkChan <- llm.StreamChunk{Error: translateHuggingFaceError(err)}
		}
	}()
	return chunkChan, nil
}

func (p *HuggingFaceProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "huggingface client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *HuggingFaceProvider) CredentialSchema() []llm.CredentialField {
	return HuggingFaceCredentialSchema()
}

func HuggingFaceCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "api_key", Label: "HuggingFace API Token", Required: true, Secret: true, Placeholder: "hf_..."},
		{Key: "base_url", Label: "TGI Endpoint (optional)", Placeholder: "https://your-tgi.example/v1", Help: "Leave empty to use the public HuggingFace Inference API."},
	}
}

func translateHuggingFaceError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "429"), strings.Contains(lower, "rate limit"):
		return llm.NewRateLimitError("huggingface")
	case strings.Contains(lower, "401"), strings.Contains(lower, "403"), strings.Contains(lower, "unauthorized"):
		return llm.NewAuthError("huggingface", err)
	case strings.Contains(lower, "400"), strings.Contains(lower, "invalid"):
		return llm.NewInvalidInputError("huggingface", err.Error())
	default:
		return llm.TranslateError("huggingface", err)
	}
}
