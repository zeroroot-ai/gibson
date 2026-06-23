package embedder

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestNewFromProvider_UnsetKindGates verifies that an empty Kind no longer
// silently yields a bundled embedder (ADR-0059 §4, gibson#810). The live path
// must hit the onboarding gate so vector features prompt the user to configure
// an embedding provider instead of producing mock embeddings.
func TestNewFromProvider_UnsetKindGates(t *testing.T) {
	emb, err := NewFromProvider(Config{})
	require.Error(t, err, "empty Kind must gate, not fall back to the bundled mock")
	assert.Nil(t, emb)
	var gerr *types.GibsonError
	require.True(t, errors.As(err, &gerr))
	assert.Equal(t, ErrCodeNoEmbeddingProvider, gerr.Code)
}

// TestNewMockEmbedder_ForTests confirms the bundled mock is still constructible
// directly — it is retained strictly for tests/fixtures that need a
// deterministic offline embedder.
func TestNewMockEmbedder_ForTests(t *testing.T) {
	emb := NewMockEmbedder()
	assert.Equal(t, 384, emb.Dimensions())
	assert.Equal(t, DefaultEmbeddingModel, emb.Model())
}

// TestNewFromProvider_Selection verifies provider+model dispatch to the right
// concrete impl with the right model-derived dimension.
func TestNewFromProvider_Selection(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantDim int
		assert  func(t *testing.T, e Embedder)
	}{
		{
			name:    "openai text-embedding-3-small → 1536",
			cfg:     Config{Kind: KindOpenAI, Model: "text-embedding-3-small", APIKey: "sk-test"},
			wantDim: 1536,
			assert:  func(t *testing.T, e Embedder) { assert.IsType(t, &openAIEmbedder{}, e) },
		},
		{
			name:    "openai text-embedding-3-large → 3072",
			cfg:     Config{Kind: KindOpenAI, Model: "text-embedding-3-large", APIKey: "sk-test"},
			wantDim: 3072,
		},
		{
			name:    "openai-compatible/TEI air-gap → table dim",
			cfg:     Config{Kind: KindOpenAICompatible, Model: "text-embedding-3-small", BaseURL: "https://embed.example.com", AllowPrivateEndpoint: true},
			wantDim: 1536,
			assert:  func(t *testing.T, e Embedder) { assert.IsType(t, &openAIEmbedder{}, e) },
		},
		{
			name:    "tei native → table dim",
			cfg:     Config{Kind: KindTEI, Model: "all-MiniLM-L6-v2", BaseURL: "https://tei.example.com", AllowPrivateEndpoint: true},
			wantDim: 384,
			assert:  func(t *testing.T, e Embedder) { assert.IsType(t, &teiEmbedder{}, e) },
		},
		{
			name:    "cohere → 1024",
			cfg:     Config{Kind: KindCohere, Model: "embed-english-v3.0", APIKey: "co-test"},
			wantDim: 1024,
			assert:  func(t *testing.T, e Embedder) { assert.IsType(t, &cohereEmbedder{}, e) },
		},
		{
			name:    "voyage → 1024",
			cfg:     Config{Kind: KindVoyage, Model: "voyage-3", APIKey: "vo-test"},
			wantDim: 1024,
			assert:  func(t *testing.T, e Embedder) { assert.IsType(t, &voyageEmbedder{}, e) },
		},
		{
			name:    "kind is case-insensitive",
			cfg:     Config{Kind: Kind("OpenAI"), Model: "text-embedding-ada-002", APIKey: "sk-test"},
			wantDim: 1536,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			emb, err := NewFromProvider(c.cfg)
			require.NoError(t, err)
			assert.Equal(t, c.wantDim, emb.Dimensions())
			assert.Equal(t, c.cfg.Model, emb.Model())
			// The selected model's dimension must be registered so the index sizes
			// from the same source of truth.
			dim, ok := DimensionForModel(c.cfg.Model)
			require.True(t, ok)
			assert.Equal(t, c.wantDim, dim)
			if c.assert != nil {
				c.assert(t, emb)
			}
		})
	}
}

func TestNewFromProvider_UnknownKindFailsClosed(t *testing.T) {
	_, err := NewFromProvider(Config{Kind: "made-up-provider", Model: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown embedding provider kind")
}

func TestNewFromProvider_UnknownModelFailsClosed(t *testing.T) {
	// An unknown model has no registered dimension; constructing must fail closed
	// rather than guess (a wrong VECTOR dim silently breaks RediSearch indexing).
	_, err := NewFromProvider(Config{Kind: KindOpenAI, Model: "gpt-not-an-embed-model", APIKey: "sk-test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown embedding model")
}

func TestNewFromProvider_MissingModelFailsClosed(t *testing.T) {
	_, err := NewFromProvider(Config{Kind: KindOpenAI, APIKey: "sk-test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a model")
}

func TestNewFromProvider_MissingCredentials(t *testing.T) {
	_, err := NewFromProvider(Config{Kind: KindOpenAI, Model: "text-embedding-3-small"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestNewFromProvider_OpenAICompatibleRequiresBaseURL(t *testing.T) {
	_, err := NewFromProvider(Config{Kind: KindOpenAICompatible, Model: "text-embedding-3-small"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url")
}

// TestNewFromProvider_SSRFGuard verifies a tenant-supplied private endpoint is
// rejected unless AllowPrivateEndpoint is set.
func TestNewFromProvider_SSRFGuard(t *testing.T) {
	_, err := NewFromProvider(Config{Kind: KindTEI, Model: "all-MiniLM-L6-v2", BaseURL: "http://169.254.169.254/embed"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked address")

	// Bypassed for operators running a local embedder.
	_, err = NewFromProvider(Config{Kind: KindTEI, Model: "all-MiniLM-L6-v2", BaseURL: "http://169.254.169.254/embed", AllowPrivateEndpoint: true})
	require.NoError(t, err)
}

func TestRegisterModelDimension_UnlocksOutOfTableModel(t *testing.T) {
	// An operator self-hosting a model not in the built-in table registers its
	// dimension first; then the factory accepts it (air-gap path).
	RegisterModelDimension("custom-airgap-embed-768", 768)
	emb, err := NewFromProvider(Config{
		Kind:                 KindOpenAICompatible,
		Model:                "custom-airgap-embed-768",
		BaseURL:              "https://embed.internal.example.com",
		AllowPrivateEndpoint: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 768, emb.Dimensions())
}
