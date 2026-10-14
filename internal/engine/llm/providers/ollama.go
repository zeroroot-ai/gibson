// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"net/http"
	"strings"

	einoollama "github.com/cloudwego/eino-ext/components/model/ollama"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// OllamaProvider implements LLMProvider for local Ollama models.
//
// NOTE: OllamaProvider does NOT implement StructuredOutputProvider.
// Ollama does not have native structured output support (no JSON mode).
// Attempting to use structured output with Ollama will fail with
// ErrStructuredOutputNotSupported at the SDK/manager level.
type OllamaProvider struct {
	model  *einoollama.ChatModel
	config llm.ProviderConfig

	listClient *http.Client
	listBase   string
	cache      modelCache
}

// NewOllamaProvider creates a new Ollama provider backed by the Eino Ollama component.
func NewOllamaProvider(cfg llm.ProviderConfig) (*OllamaProvider, error) {
	serverURL := cfg.BaseURL
	if serverURL == "" {
		serverURL = "http://localhost:11434"
	}

	if err := validateLLMEndpoint(serverURL, cfg.AllowPrivateEndpoint); err != nil {
		return nil, err
	}

	client := guardedHTTPClient(cfg)
	einoConfig := &einoollama.ChatModelConfig{
		BaseURL:    serverURL,
		Model:      cfg.DefaultModel,
		HTTPClient: client,
	}
	m, err := einoollama.NewChatModel(context.Background(), einoConfig)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return &OllamaProvider{
		model:      m,
		config:     cfg,
		listClient: client,
		listBase:   serverURL,
	}, nil
}

// Name returns the provider name
func (p *OllamaProvider) Name() string {
	return "ollama"
}

// Models asks the Ollama server (GET {base}/api/tags) for the models that are
// pulled on it. Ollama reports no context window here, so the field stays zero.
func (p *OllamaProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return p.cache.get(ctx, "ollama", func(ctx context.Context) ([]llm.ModelInfo, error) {
		header := http.Header{}
		if p.config.APIKey != "" {
			header.Set("Authorization", "Bearer "+p.config.APIKey)
		}
		var tags struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		if err := getJSON(ctx, p.listClient, "ollama", strings.TrimRight(p.listBase, "/")+"/api/tags", header, &tags); err != nil {
			return nil, err
		}
		models := make([]llm.ModelInfo, 0, len(tags.Models))
		for _, m := range tags.Models {
			if m.Name == "" {
				continue
			}
			models = append(models, llm.ModelInfo{Name: m.Name, Features: []string{"chat"}})
		}
		return models, nil
	})
}

// Complete sends a completion request
func (p *OllamaProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)

	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return fromEinoMessage(out, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *OllamaProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return fromEinoMessage(out, req.Model), nil
}

// Stream sends a streaming completion request
func (p *OllamaProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)

	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("ollama", err)
	}

	return streamToChannel(sr, req.Model, func(e error) error { return llm.TranslateError("ollama", e) }), nil
}

// Health checks the provider health
func (p *OllamaProvider) Health(ctx context.Context) types.HealthStatus {
	req := llm.CompletionRequest{
		Model: p.config.DefaultModel,
		Messages: []llm.Message{
			llm.NewUserMessage("test"),
		},
		MaxTokens: 1,
	}

	_, err := p.Complete(ctx, req)
	if err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}

	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// DefaultModel returns the default model saved for this provider, or "".
func (p *OllamaProvider) DefaultModel() string { return p.config.DefaultModel }

// DefaultModelContextWindow returns the context window stored with the saved
// default model, or 0 when none is stored.
func (p *OllamaProvider) DefaultModelContextWindow() int { return p.config.DefaultModelContextWindow }
