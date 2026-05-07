package embedder

import (
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/types"
)

// EmbedderType represents available embedder implementations.
type EmbedderType string

const (
	// EmbedderTypeNative uses all-MiniLM-L6-v2 for local offline embedding generation.
	// No API keys required, runs via GoMLX with XLA/PJRT backend.
	// Produces 384-dimensional embeddings.
	EmbedderTypeNative EmbedderType = "native"
)

// CreateEmbedder creates an embedder based on the provided configuration.
//
// Supported provider types:
//   - "native": all-MiniLM-L6-v2 (384 dims, offline, no API key) - DEFAULT
//   - "" (empty): defaults to native
//
// Returns an error if embedder initialization fails. The daemon should fail fast
// if the embedder cannot be created - vector search is a core feature.
func CreateEmbedder(config EmbedderConfig, logger *slog.Logger) (Embedder, error) {
	switch EmbedderType(config.Provider) {
	case EmbedderTypeNative, "":
		return CreateNativeEmbedder(logger)

	default:
		return nil, types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("unknown embedder provider '%s' - must be 'native'",
				config.Provider))
	}
}

// ValidateEmbedderConfig validates an embedder configuration.
// Returns an error if the configuration is invalid or incomplete.
func ValidateEmbedderConfig(config EmbedderConfig) error {
	switch EmbedderType(config.Provider) {
	case EmbedderTypeNative, "":
		// Native embedder has no additional config requirements
		// Empty provider defaults to native
		return nil

	default:
		return types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("unknown embedder provider '%s' - must be 'native'",
				config.Provider))
	}
}
