package providers

import (
	"context"
	"strings"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// LlamafileProvider talks to a llamafile / llama.cpp HTTP server through its
// OpenAI-compatible endpoint via the Eino OpenAI ChatModel.
//
// Self-hosted — no API key. The server defaults to http://localhost:8080;
// operators may override via cfg.BaseURL. The OpenAI-compatible routes live
// under /v1, so the BaseURL is normalised to end with /v1.
type LlamafileProvider struct {
	model  *einoopenai.ChatModel
	config llm.ProviderConfig
}

// NewLlamafileProvider constructs a Llamafile-backed provider.
func NewLlamafileProvider(cfg llm.ProviderConfig) (*LlamafileProvider, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:8080/v1"
	} else if !strings.HasSuffix(baseURL, "/v1") {
		baseURL = strings.TrimSuffix(baseURL, "/") + "/v1"
	}

	m, err := einoopenai.NewChatModel(context.Background(), &einoopenai.ChatModelConfig{
		APIKey:  "llamafile", // dummy key; llamafile doesn't require auth
		Model:   cfg.DefaultModel,
		BaseURL: baseURL,
	})
	if err != nil {
		return nil, llm.TranslateError("llamafile", err)
	}
	return &LlamafileProvider{model: m, config: cfg}, nil
}

func (p *LlamafileProvider) Name() string { return "llamafile" }

func (p *LlamafileProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	// Llamafile is a single-binary server; Models() reports one synthetic
	// entry identified by the configured DefaultModel.
	name := p.config.DefaultModel
	if name == "" {
		name = "llamafile-local"
	}
	return []llm.ModelInfo{
		{Name: name, ContextWindow: 4096, MaxOutput: 2048, Features: []string{"chat", "streaming"}},
	}, nil
}

func (p *LlamafileProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("llamafile", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

func (p *LlamafileProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}

func (p *LlamafileProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("llamafile", err)
	}
	return streamToChannel(sr, func(e error) error { return llm.TranslateError("llamafile", e) }), nil
}

func (p *LlamafileProvider) Health(_ context.Context) types.HealthStatus {
	if p.model == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "llamafile client not initialised")
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *LlamafileProvider) CredentialSchema() []llm.CredentialField {
	return LlamafileCredentialSchema()
}

func LlamafileCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		// Llamafile is self-hosted — no credentials required. The only field
		// we surface is default_model so operators can label their deployment.
	}
}
