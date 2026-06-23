package embedder

import "strings"

// This file is the single source of truth mapping an embedding model to its
// output vector dimension. The vector store index and KNN search derive their
// dimension from the configured embedding model through these helpers — the
// dimension is never hardcoded at a call site (ADR-0027 wholesale discipline,
// gibson#807).
//
// E11 makes embeddings bring-your-own per tenant: the model comes from the
// tenant's provider config (default_embedding_model) and the dimension is
// derived here. The provider-backed embedder factory (gibson#808) extends this
// table — it does not introduce a second mapping.

// DefaultEmbeddingModel is the model the bundled/default embedder reports. It
// resolves to 384 through DimensionForModel, preserving the historical
// all-MiniLM-L6-v2 behaviour without hardcoding the number.
const DefaultEmbeddingModel = "all-MiniLM-L6-v2"

// DefaultEmbeddingDimension is the dimension of the default embedding model.
// It is derived from DefaultEmbeddingModel, not written as a literal, so the
// model table stays the only place a dimension is declared.
var DefaultEmbeddingDimension = mustDimensionForModel(DefaultEmbeddingModel)

// modelDimensions maps a normalised embedding-model name to its output
// dimension. Keys are lower-cased; lookups go through normalizeModel.
//
// Keep this table minimal but correct. gibson#808's provider-backed embedder
// factory (OpenAI, Bedrock/Titan, Cohere, Voyage, generic OpenAI-compatible/TEI)
// registers any additional models it serves via RegisterModelDimension at init
// time, or extends this literal table directly — either way this remains the
// single source of truth.
var modelDimensions = map[string]int{
	// Bundled / default sentence-transformer (all-MiniLM-L6-v2).
	"all-minilm-l6-v2":  384,
	"all-minilm-l12-v2": 384,

	// OpenAI.
	"text-embedding-3-small": 1536,
	"text-embedding-3-large": 3072,
	"text-embedding-ada-002": 1536,

	// AWS Bedrock — Amazon Titan Text Embeddings.
	"amazon.titan-embed-text-v1":   1536,
	"amazon.titan-embed-text-v2:0": 1024,

	// Cohere (Bedrock + native).
	"cohere.embed-english-v3":      1024,
	"cohere.embed-multilingual-v3": 1024,
	"embed-english-v3.0":           1024,
	"embed-multilingual-v3.0":      1024,

	// Voyage AI.
	"voyage-3":       1024,
	"voyage-3-lite":  512,
	"voyage-large-2": 1536,
}

// normalizeModel lower-cases and trims a model name for table lookup so callers
// need not worry about casing or surrounding whitespace.
func normalizeModel(model string) string {
	return strings.ToLower(strings.TrimSpace(model))
}

// SameModel reports whether two embedding-model names refer to the same model,
// applying the same normalisation (lower-case, trim) used for the dimension
// table lookup. Used by the re-embed job (gibson#809) to detect a model change
// without being fooled by casing or surrounding whitespace.
func SameModel(a, b string) bool {
	return normalizeModel(a) == normalizeModel(b)
}

// DimensionForModel returns the output vector dimension for an embedding model
// and whether the model is known. An unknown model returns (0, false): the
// caller must fail closed rather than guess a dimension, because a wrong VECTOR
// field dimension silently fails RediSearch indexing of the whole document.
func DimensionForModel(model string) (int, bool) {
	dim, ok := modelDimensions[normalizeModel(model)]
	return dim, ok
}

// RegisterModelDimension records the output dimension for an embedding model.
// gibson#808's provider factory calls this at init for the models it serves so
// that a single source of truth backs both the embedder and the vector index.
// It is safe to re-register an identical mapping; registering a conflicting
// dimension for an already-known model panics, surfacing the contradiction at
// startup rather than corrupting an index at runtime.
func RegisterModelDimension(model string, dim int) {
	key := normalizeModel(model)
	if existing, ok := modelDimensions[key]; ok && existing != dim {
		panic("embedder: conflicting dimension registered for model " + model)
	}
	modelDimensions[key] = dim
}

// mustDimensionForModel returns the dimension for a model that is expected to be
// in the table; it panics otherwise. Used only for package-level derivation of
// well-known constants (e.g. the default model), never on a request path.
func mustDimensionForModel(model string) int {
	dim, ok := DimensionForModel(model)
	if !ok {
		panic("embedder: no dimension registered for model " + model)
	}
	return dim
}
