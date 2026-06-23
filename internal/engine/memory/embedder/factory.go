package embedder

import (
	"fmt"
	"net/http"
	"strings"
	"time"

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

	// KindVoyage is Voyage AI's /v1/embeddings endpoint.
	KindVoyage Kind = "voyage"
)

// Config is the provider-agnostic input the factory maps to a concrete
// Embedder. It is deliberately decoupled from the provider proto so this
// package stays infra-light and easy to unit-test: the daemon's provider
// handler translates a gibson.tenant.v1.ProviderRecord (type, credentials,
// default_embedding_model) into this struct at the wiring seam.
type Config struct {
	// Kind selects the backend. Empty selects the bundled mock default.
	Kind Kind

	// Model is the embedding model to use — typically the provider's
	// default_embedding_model. Required for every non-bundled backend; it both
	// selects the upstream model and (via RegisterModelDimension /
	// DimensionForModel) sizes the vector index.
	Model string

	// APIKey is the provider API key for HTTP backends (OpenAI, Cohere, Voyage,
	// and OpenAI-compatible/TEI endpoints that require auth). Bedrock ignores it
	// and uses the AWS credential chain instead.
	APIKey string

	// BaseURL overrides the upstream endpoint. Required for the generic
	// OpenAI-compatible and TEI backends (the self-host / air-gap path); optional
	// for OpenAI (defaults to https://api.openai.com).
	BaseURL string

	// Region is the AWS region for the Bedrock backend. Falls back to AWS_REGION
	// then us-east-1.
	Region string

	// Extra carries provider-specific credentials/options that do not map to the
	// fields above — e.g. Bedrock's aws_access_key_id / aws_secret_access_key /
	// use_irsa. Keys mirror the provider's CredentialField keys.
	Extra map[string]string

	// AllowPrivateEndpoint disables the SSRF guard on BaseURL. The daemon sets
	// this from security.allow_private_llm_endpoints for operators running a
	// local/in-cluster embedder. Off by default: tenant-supplied endpoints
	// resolving to private/link-local/metadata addresses are rejected.
	AllowPrivateEndpoint bool

	// Timeout bounds a single embedding request. Zero uses defaultTimeout.
	Timeout time.Duration

	// HTTPClient is injected by tests to stub upstream responses. Nil uses a
	// package default client honouring Timeout.
	HTTPClient *http.Client
}

const defaultTimeout = 30 * time.Second

// builder constructs a concrete Embedder from a Config. The factory registry
// maps a Kind to one of these.
type builder func(Config) (Embedder, error)

// registry maps a provider Kind to its Embedder builder. It is the single
// dispatch table the factory keys on; adding a backend means adding one entry.
var registry = map[Kind]builder{
	KindOpenAI:           newOpenAIEmbedder,
	KindOpenAICompatible: newOpenAICompatibleEmbedder,
	KindTEI:              newTEIEmbedder,
	KindBedrock:          newBedrockEmbedder,
	KindCohere:           newCohereEmbedder,
	KindVoyage:           newVoyageEmbedder,
}

// NewFromProvider constructs the Embedder for a tenant's configured embedding
// provider. It is THE way an embedder is built (ADR-0027 wholesale): there is no
// parallel "old vs new" path.
//
// An empty Kind is the onboarding gate (ADR-0059 §4, gibson#810): the live path
// no longer silently falls back to a bundled embedder. NewFromProvider returns
// ErrNoEmbeddingProvider so the caller can surface the "configure an embedding
// provider" prompt to the user, exactly like the LLM-provider gate. Tests that
// need a deterministic offline embedder inject NewMockEmbedder() directly rather
// than relying on an empty-Kind fallback.
//
// For every backend the returned Embedder has already registered its
// model→dimension mapping (RegisterModelDimension), so the vector index sized
// from DimensionForModel(cfg.Model) matches what the embedder emits. A wrong
// dimension would silently fail RediSearch indexing of the whole document, so
// unknown models fail closed here rather than guessing.
func NewFromProvider(cfg Config) (Embedder, error) {
	if normalizeKind(cfg.Kind) == KindUnset {
		return nil, ErrNoEmbeddingProvider()
	}
	build, ok := registry[normalizeKind(cfg.Kind)]
	if !ok {
		return nil, types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("unknown embedding provider kind %q", cfg.Kind))
	}
	return build(cfg)
}

// normalizeKind lower-cases and trims a Kind so the daemon can pass a provider
// "type" string through without worrying about casing.
func normalizeKind(k Kind) Kind {
	return Kind(strings.ToLower(strings.TrimSpace(string(k))))
}

// httpClient returns the configured HTTP client or a package default honouring
// the configured (or default) timeout.
func (c Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	to := c.Timeout
	if to <= 0 {
		to = defaultTimeout
	}
	return &http.Client{Timeout: to}
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
