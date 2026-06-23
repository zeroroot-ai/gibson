package embedder

import "github.com/zeroroot-ai/gibson/internal/infra/types"

// Embedder error codes
const (
	ErrCodeEmbedderUnavailable  types.ErrorCode = "EMBEDDER_UNAVAILABLE"
	ErrCodeEmbeddingFailed      types.ErrorCode = "EMBEDDING_FAILED"
	ErrCodeEmbeddingBatchFailed types.ErrorCode = "EMBEDDING_BATCH_FAILED"
	ErrCodeInvalidConfig        types.ErrorCode = "INVALID_EMBEDDER_CONFIG"

	// ErrCodeNoEmbeddingProvider is the onboarding gate (ADR-0059 §4,
	// gibson#810): the live path requires a configured embedding provider and
	// no longer falls back to a bundled embedder. The message is passed through
	// verbatim to the caller (it carries no EMBEDDER_/VECTOR_ prefix that the
	// error-scrub interceptor would flatten), mirroring the LLM
	// LLM_NO_MATCHING_PROVIDER gate so the dashboard can prompt the user.
	ErrCodeNoEmbeddingProvider types.ErrorCode = "NO_EMBEDDING_PROVIDER"
)

// NoEmbeddingProviderMessage is the canonical user-facing prompt surfaced when a
// tenant has no embedding provider configured. It mirrors the LLM gate's
// "add one in Settings → Providers" wording so vector features fail gracefully
// with an actionable message rather than a panic or a silent mock fallback.
const NoEmbeddingProviderMessage = "no embedding provider configured for this tenant — add one in Settings → Providers (vector recall, GraphRAG, belief-RAG and finding classification require an embedding provider)"

// ErrNoEmbeddingProvider returns the canonical "configure an embedding provider"
// gate error. It is the graceful return for every vector feature when the tenant
// has no embedding provider configured.
func ErrNoEmbeddingProvider() error {
	return types.NewError(ErrCodeNoEmbeddingProvider, NoEmbeddingProviderMessage)
}
