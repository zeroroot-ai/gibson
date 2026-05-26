package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/secrets"
)

// NewProvider constructs an LLMProvider for the given ProviderConfig.Type.
// Every ProviderType in llm.SupportedProviderTypes() must have a matching case
// in this switch — the factory_coverage_test enforces that invariant.
//
// NewProvider uses context.Background() and no broker service. For broker-aware
// credential resolution use NewProviderWithContext.
func NewProvider(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	return NewProviderWithContext(context.Background(), nil, cfg)
}

// NewProviderWithContext constructs an LLMProvider with broker-aware credential
// resolution. service may be nil; when nil, credential lookup falls back to the
// cfg.Extra / cfg.APIKey / env-var chain (subject to GIBSON_DEV_ENV_FALLBACK).
//
// Every constructed provider is wrapped with a circuitLLMProvider backed by a
// sony/gobreaker circuit breaker (10 consecutive failures to open, 60 s
// interval, 60 s timeout). This prevents latency pile-up during provider
// outages. Mock and Custom providers are NOT wrapped.
//
// Phase 10 (secrets-broker, Task 28): broker-first credential resolution for
// Cloudflare, Mistral, Cohere, and HuggingFace providers. Bedrock, Anthropic,
// OpenAI, and Google providers read credentials from cfg or env-var directly
// (their credential handling is outside resolveCredential); they are not yet
// wired to the broker — that is deferred to Task 29 / Phase 11 per-provider
// rotation subscription work.
//
// TODO(Phase 11, Task 29): extend broker credential resolution to Bedrock,
// Anthropic, OpenAI, and Google providers via the same provider_config: prefix.
func NewProviderWithContext(ctx context.Context, service *secrets.Service, cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	var (
		p   llm.LLMProvider
		err error
	)

	switch cfg.Type {
	case llm.ProviderAnthropic:
		p, err = NewAnthropicProvider(cfg)
	case llm.ProviderOpenAI:
		p, err = NewOpenAIProvider(cfg)
	case llm.ProviderGoogle:
		p, err = NewGoogleProvider(cfg)
	case llm.ProviderOllama:
		p, err = NewOllamaProvider(cfg)
	case llm.ProviderBedrock:
		p, err = NewBedrockProvider(cfg)
	case llm.ProviderCloudflare:
		p, err = newCloudflareProviderWithContext(ctx, service, cfg)
	case llm.ProviderCohere:
		p, err = newCohereProviderWithContext(ctx, service, cfg)
	case llm.ProviderHuggingFace:
		p, err = newHuggingFaceProviderWithContext(ctx, service, cfg)
	case llm.ProviderLlamafile:
		p, err = NewLlamafileProvider(cfg)
	case llm.ProviderMistral:
		p, err = newMistralProviderWithContext(ctx, service, cfg)
	case llm.ProviderCustom:
		// Custom is a deliberate escape hatch for operators wiring a provider
		// the daemon doesn't know about. Construction is their responsibility;
		// the factory refuses to pretend it understands the type.
		return nil, llm.NewInvalidInputError("factory",
			"ProviderCustom cannot be constructed by the factory; build the provider directly")
	case "mock":
		// Mock provider is used in tests only; skip circuit-breaker wrapping so
		// test helpers can inspect raw call counts without breaker interference.
		return NewMockProvider([]string{"Mock response"}), nil
	default:
		return nil, llm.NewInvalidInputError("factory",
			fmt.Sprintf("unknown provider type %q; supported: %s", cfg.Type, supportedTypesList()))
	}

	if err != nil {
		return nil, err
	}
	return newCircuitLLMProvider(p, p.Name()), nil
}

// supportedTypesList returns the enum as a comma-separated list for error messages.
func supportedTypesList() string {
	types := llm.SupportedProviderTypes()
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, string(t))
	}
	return strings.Join(names, ", ")
}
