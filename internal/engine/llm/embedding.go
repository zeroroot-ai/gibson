package llm

import "context"

// EmbeddingProvider is the optional interface implemented by LLM providers that
// support generating vector embeddings from text. Providers that do not support
// embeddings (e.g. Anthropic) should not implement this interface; the registry
// will return ErrEmbeddingsNotSupported when no qualifying provider is found.
//
// Consumers should use LLMRegistry.GetEmbeddingProvider() to obtain an instance
// rather than type-asserting LLMProvider directly.
type EmbeddingProvider interface {
	// Embed generates vector embeddings for a batch of input texts.
	// Each element in the returned slice corresponds to the same-indexed element
	// of the texts parameter. The dimensionality of each vector is determined by
	// the underlying model and is consistent across calls.
	//
	// Returns ErrEmbeddingsNotSupported if the provider's current model does not
	// support embeddings. Returns a non-nil error on any API or network failure.
	Embed(ctx context.Context, texts []string) ([][]float64, error)

	// SupportsEmbeddings reports whether this provider can generate embeddings
	// with its current configuration. Implementations may return false when the
	// selected model does not support the embeddings endpoint even if the API
	// client itself would allow it.
	SupportsEmbeddings() bool
}
