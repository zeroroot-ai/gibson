package providers

import (
	"context"

	"github.com/tmc/langchaingo/llms/llamafile"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// LlamafileProvider wraps langchaingo's llamafile integration.
//
// Self-hosted — no API key. The upstream llamafileclient defaults to
// http://localhost:8080. langchaingo v0.1.14 does not expose a public setter
// for the server URL, so operators who need a non-default host should run
// their llamafile binary with --host/--port matching the daemon's
// reachability assumptions.
type LlamafileProvider struct {
	client *llamafile.LLM
	config llm.ProviderConfig
}

// NewLlamafileProvider constructs a Llamafile-backed provider.
func NewLlamafileProvider(cfg llm.ProviderConfig) (*LlamafileProvider, error) {
	var opts []llamafile.Option
	if cfg.DefaultModel != "" {
		opts = append(opts, llamafile.WithModel(cfg.DefaultModel))
	}
	client, err := llamafile.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("llamafile", err)
	}
	return &LlamafileProvider{client: client, config: cfg}, nil
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
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, llm.TranslateError("llamafile", err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *LlamafileProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}

func (p *LlamafileProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
			chunkChan <- llm.StreamChunk{Error: llm.TranslateError("llamafile", err)}
		}
	}()
	return chunkChan, nil
}

func (p *LlamafileProvider) Health(_ context.Context) types.HealthStatus {
	if p.client == nil {
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
