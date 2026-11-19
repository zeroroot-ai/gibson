// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package embedder

import (
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Kind identifies an embedding-provider backend. It is the discriminator the
// factory keys on to pick a concrete Embedder implementation. Values are the
// lower-cased provider "type" strings the tenant provider config carries
// (gibson.tenant.v1.ProviderRecord.type), so the daemon can pass them through
// verbatim.
type Kind string

const (
	// KindUnset is the zero value: no embedding provider configured. The live
	// path treats it as the onboarding gate (ADR-0059 §4, gibson#810):
	// NewFromProvider returns ErrNoEmbeddingProvider rather than a bundled mock
	// fallback. The bundled MockEmbedder is retained for tests/fixtures only and
	// must be injected explicitly via NewMockEmbedder().
	KindUnset Kind = ""

	// KindOpenAI is OpenAI's /v1/embeddings endpoint.
	KindOpenAI Kind = "openai"

	// KindOpenAICompatible is a generic OpenAI-compatible /v1/embeddings
	// endpoint — including HuggingFace Text-Embeddings-Inference (TEI) run in
	// "openai" compatibility mode. This is the air-gap path: point BaseURL at a
	// self-hosted embedder and bring your own model + dimension.
	KindOpenAICompatible Kind = "openai-compatible"

	// KindTEI is HuggingFace Text-Embeddings-Inference addressed through its
	// native /embed endpoint (not the OpenAI-compatible shim). Also air-gappable.
	KindTEI Kind = "tei"

	// KindBedrock is AWS Bedrock Amazon Titan Text Embeddings via the
	// bedrockruntime InvokeModel API.
	KindBedrock Kind = "bedrock"

	// KindCohere is Cohere's native /v1/embed endpoint.
	KindCohere Kind = "cohere"

	// KindVoyage is refused: the gateway does not accept the reply of Voyage.
	KindVoyage Kind = "voyage"
)

// Config is the input of the factory. The embedder holds no credential and no
// endpoint: the model gateway holds both for the provider of the tenant.
type Config struct {
	// Kind is the type of the provider record. It must be a kind that serves
	// embeddings. Voyage is refused.
	Kind Kind

	// Model is the exact embedding model name, typically the default
	// embedding model of the provider. Required. It selects the upstream model
	// and, through the model table, the dimension of the vector index.
	Model string

	// Tenant and Provider name the route: the ModelProvider of the tenant.
	Tenant   string
	Provider string

	// Gateway sends the call. The model client of the daemon implements it.
	Gateway Gateway
}

// ErrVoyageNotSupported is the message for the voyage kind.
const voyageRefusal = "voyage is not an embedding provider type: the model gateway does not accept its reply. " +
	"Use openai, openai-compatible, tei, bedrock or cohere"

// NewFromProvider constructs the Embedder for a tenant's configured embedding
// provider. It is THE way an embedder is built (ADR-0027 wholesale): there is no
// parallel "old vs new" path. All kinds go through the one gateway client.
//
// An empty Kind is the onboarding gate (ADR-0059 §4, gibson#810): the live path
// returns ErrNoEmbeddingProvider so the caller can surface the "configure an
// embedding provider" prompt to the user. Tests that need a deterministic
// offline embedder inject NewMockEmbedder() directly.
//
// The returned Embedder has registered its model→dimension mapping
// (RegisterModelDimension), so the vector index sized from
// DimensionForModel(cfg.Model) matches what the embedder emits. Unknown models
// fail closed here rather than guessing.
func NewFromProvider(cfg Config) (Embedder, error) {
	switch kind := normalizeKind(cfg.Kind); kind {
	case KindUnset:
		return nil, ErrNoEmbeddingProvider()
	case KindVoyage:
		return nil, types.NewError(ErrCodeInvalidConfig, voyageRefusal)
	case KindOpenAI, KindOpenAICompatible, KindTEI, KindBedrock, KindCohere:
		cfg.Kind = kind
		return newGatewayEmbedder(cfg)
	default:
		return nil, types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("unknown embedding provider kind %q", cfg.Kind))
	}
}

// normalizeKind lower-cases and trims a Kind so the daemon can pass a provider
// "type" string through without worrying about casing.
func normalizeKind(k Kind) Kind {
	return Kind(strings.ToLower(strings.TrimSpace(string(k))))
}

// requireModel returns the configured model or a fail-closed error. Every
// non-bundled backend needs an explicit model: it both selects the upstream
// model and sizes the vector index.
func (c Config) requireModel(provider string) (string, error) {
	model := strings.TrimSpace(c.Model)
	if model == "" {
		return "", types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("%s embedder requires a model (provider default_embedding_model)", provider))
	}
	return model, nil
}
