package providers

import (
	"context"
	"fmt"
	"os"

	"github.com/tmc/langchaingo/llms/local"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// LocalProvider wraps langchaingo's subprocess-based local LLM runner.
// It spawns the binary named in cfg.Extra["bin"] (or LOCAL_LLM_BIN env) and
// pipes prompts via stdin. This is a dev convenience for running raw
// llama.cpp / gpt4all / similar binaries on the same host as the daemon;
// it is not appropriate for production use.
//
// For OpenAI-compatible HTTP endpoints (vLLM, LM Studio, text-generation-webui)
// use ProviderType=openai with a custom BaseURL — that path already exists.
type LocalProvider struct {
	client *local.LLM
	config llm.ProviderConfig
	bin    string
}

// NewLocalProvider constructs a Local subprocess-backed provider.
func NewLocalProvider(cfg llm.ProviderConfig) (*LocalProvider, error) {
	bin := cfg.Extra["bin"]
	if bin == "" {
		bin = os.Getenv("LOCAL_LLM_BIN")
	}
	if bin == "" {
		return nil, llm.NewInvalidInputError("local",
			"local provider requires cfg.Extra[\"bin\"] or LOCAL_LLM_BIN env var to point at a binary")
	}

	// langchaingo's llms/local reads LOCAL_LLM_BIN at construction via
	// WithBin — surface our resolved value regardless of how it was sourced.
	opts := []local.Option{local.WithBin(bin)}
	if args := cfg.Extra["args"]; args != "" {
		opts = append(opts, local.WithArgs(args))
	}

	client, err := local.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("local", err)
	}
	return &LocalProvider{client: client, config: cfg, bin: bin}, nil
}

func (p *LocalProvider) Name() string { return "local" }

// Models returns a single synthetic entry identified by cfg.DefaultModel (or
// "local-model" if unset). Feature flags are taken from cfg.Extra["features"]
// (comma-separated) since a raw binary cannot be introspected.
func (p *LocalProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	name := p.config.DefaultModel
	if name == "" {
		name = "local-model"
	}
	features := parseCSV(p.config.Extra["features"])
	if len(features) == 0 {
		features = []string{"chat"}
	}
	return []llm.ModelInfo{
		{Name: name, ContextWindow: 4096, MaxOutput: 2048, Features: features},
	}, nil
}

func (p *LocalProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, llm.TranslateError("local", err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

func (p *LocalProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}

func (p *LocalProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	// langchaingo's local runner does not stream token-level output — it
	// buffers the subprocess output and returns at end. Emit the full payload
	// as a single chunk for API compatibility.
	chunkChan := make(chan llm.StreamChunk, 2)
	go func() {
		defer close(chunkChan)
		resp, err := p.Complete(ctx, req)
		if err != nil {
			chunkChan <- llm.StreamChunk{Error: err}
			return
		}
		chunkChan <- llm.StreamChunk{Delta: llm.StreamDelta{Content: resp.Message.Content}}
	}()
	return chunkChan, nil
}

func (p *LocalProvider) Health(_ context.Context) types.HealthStatus {
	if _, err := os.Stat(p.bin); err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy,
			fmt.Sprintf("local binary %q not accessible: %v", p.bin, err))
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

func (p *LocalProvider) CredentialSchema() []llm.CredentialField { return LocalCredentialSchema() }

func LocalCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "bin", Label: "Binary path", Required: true, Placeholder: "/usr/local/bin/llama"},
		{Key: "args", Label: "Additional args (optional)", Placeholder: "--threads 4 --ctx-size 4096"},
		{Key: "features", Label: "Declared features (CSV)", Placeholder: "chat,streaming"},
	}
}

// parseCSV splits "a, b , c" into ["a","b","c"] — empty entries skipped.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			seg := trimSpaces(s[start:i])
			if seg != "" {
				out = append(out, seg)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpaces(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
