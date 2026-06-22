package embedder

import (
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// EmbedderType represents available embedder implementations.
type EmbedderType string

const (
	// EmbedderTypeProvider resolves a provider-backed embedder from the tenant's
	// configured embedding provider (mirrors the LLM ProviderService — see
	// docs ADR-0059). It is the only supported embedder type: gibson no longer
	// bundles a local model.
	EmbedderTypeProvider EmbedderType = "provider"
)

// CreateEmbedder resolves an Embedder for the given configuration.
//
// Per docs ADR-0059 the bundled ONNX embedder has been removed. Embedding is a
// BYO provider: the concrete impl is resolved from the tenant's configured
// embedding provider (OpenAI / Bedrock / Cohere / Voyage / generic
// OpenAI-compatible-or-TEI endpoint). The provider-backed factory and the
// per-tenant re-embed migration are a follow-up build; until they land, gibson
// has no in-process fallback. There is deliberately NO bundled soft-degrade:
// vector recall / GraphRAG / belief-RAG / finding vector classification are
// gated until an embedding provider is configured, exactly as the LLM-provider
// requirement gates chat (ADR-0059 §4).
func CreateEmbedder(config EmbedderConfig, logger *slog.Logger) (Embedder, error) {
	return nil, types.NewError(ErrCodeEmbedderUnavailable,
		fmt.Sprintf("no embedding provider configured (provider=%q): gibson no longer "+
			"bundles a local embedder — configure a BYO embedding provider (docs ADR-0059)",
			config.Provider))
}

// ValidateEmbedderConfig validates an embedder configuration.
// Returns an error if the configuration is invalid or incomplete.
func ValidateEmbedderConfig(config EmbedderConfig) error {
	return config.Validate()
}
