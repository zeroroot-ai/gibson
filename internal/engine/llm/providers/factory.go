// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// NewProvider constructs an LLMProvider for the given ProviderConfig.Type.
// Every ProviderType in llm.SupportedProviderTypes() must have a matching case
// in this switch — the factory_coverage_test enforces that invariant.
//
// NewProvider uses context.Background(). For an explicit context (e.g. the
// per-provider clients that take one) use NewProviderWithContext.
func NewProvider(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	return NewProviderWithContext(context.Background(), cfg)
}

// NewProviderWithContext constructs an LLMProvider from cfg. Credentials come
// from cfg.APIKey/cfg.Extra, which the tenant provider resolver populates from
// the secrets broker before the factory runs (see
// tenantprovider.decryptedToLLMConfig); resolveCredential also honours the
// dev-only GIBSON_DEV_ENV_FALLBACK env chain.
//
// Every constructed provider is wrapped with a circuitLLMProvider backed by a
// sony/gobreaker circuit breaker (10 consecutive failures to open, 60 s
// interval, 60 s timeout). This prevents latency pile-up during provider
// outages. Mock and Custom providers are NOT wrapped.
func NewProviderWithContext(ctx context.Context, cfg llm.ProviderConfig) (llm.LLMProvider, error) {
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
		p, err = newCloudflareProviderWithContext(ctx, cfg)
	case llm.ProviderCohere:
		p, err = newCohereProviderWithContext(ctx, cfg)
	case llm.ProviderHuggingFace:
		p, err = newHuggingFaceProviderWithContext(ctx, cfg)
	case llm.ProviderLlamafile:
		p, err = NewLlamafileProvider(cfg)
	case llm.ProviderVertex:
		p, err = NewVertexProvider(ctx, cfg)
	case llm.ProviderFoundry:
		p, err = NewFoundryProvider(ctx, cfg)
	case llm.ProviderMistral:
		p, err = newMistralProviderWithContext(ctx, cfg)
	case llm.ProviderVoyage, llm.ProviderOpenAICompatible, llm.ProviderTEI:
		// Embedding-only providers (E11 BYO-embedder, ADR-0059): these types are
		// valid in ProviderConfigInput when CAPABILITY_EMBEDDING is declared, but
		// they cannot serve chat completions. Use embedder.NewFromProvider instead.
		return nil, fmt.Errorf("%w",
			llm.NewInvalidInputError("factory",
				fmt.Sprintf("provider type %q is embedding-only and cannot be used for chat completions; use the embedder API instead", cfg.Type)))
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
