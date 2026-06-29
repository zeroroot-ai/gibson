package api

// server_provider_probe_test.go — unit tests for gibson#1012 (embedding
// capabilities catalogue) and gibson#1013 (embedding probe in TestProvider /
// ProbeProvider implementation).
//
// Test strategy:
//   - All tests are pure in-process; no real LLM API, no network.
//   - stubEmbedderFactory injects a deterministic in-process embedder via
//     WithEmbedderFactory so the probe path can be exercised without real
//     upstream HTTP calls.
//   - stubErrorEmbedderFactory exercises the failure path.
//   - GetSupportedProviders shape tests verify the embedding_models field
//     is populated for providers that have catalogue entries.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// ---------------------------------------------------------------------------
// Embedder factory stubs
// ---------------------------------------------------------------------------

// stubSuccessEmbedderFactory returns a MockEmbedder that always succeeds.
func stubSuccessEmbedderFactory(_ embedder.Config) (embedder.Embedder, error) {
	return embedder.NewMockEmbedder(), nil
}

// stubErrorEmbedderFactory returns an error unconditionally.
func stubErrorEmbedderFactory(_ embedder.Config) (embedder.Embedder, error) {
	return nil, errors.New("upstream embedder unavailable")
}

// ---------------------------------------------------------------------------
// GetSupportedProviders — embedding_models shape (gibson#1012)
// ---------------------------------------------------------------------------

// TestGetSupportedProviders_OpenAI_HasEmbeddingModels verifies the openai
// descriptor surfaces embedding models in the new embedding_models field.
func TestGetSupportedProviders_OpenAI_HasEmbeddingModels(t *testing.T) {
	s := blankServer()
	resp, err := s.GetSupportedProviders(tenantCtx("acme"), &tenantv1.GetSupportedProvidersRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	var openai *tenantv1.SupportedProvider
	for _, p := range resp.Providers {
		if p.Type == "openai" {
			openai = p
			break
		}
	}
	require.NotNil(t, openai, "openai provider must be present in catalogue")
	assert.NotEmpty(t, openai.EmbeddingModels, "openai must advertise embedding models")
	assert.NotEmpty(t, openai.DefaultModels, "openai must still advertise chat models")

	// All embedding models must carry CAPABILITY_EMBEDDING.
	for _, m := range openai.EmbeddingModels {
		assert.Contains(t, m.Capabilities, tenantv1.Capability_CAPABILITY_EMBEDDING,
			"embedding model %q must carry CAPABILITY_EMBEDDING", m.Name)
		assert.NotContains(t, m.Capabilities, tenantv1.Capability_CAPABILITY_CHAT,
			"embedding model %q must not carry CAPABILITY_CHAT", m.Name)
	}
}

// TestGetSupportedProviders_Bedrock_HasEmbeddingModels verifies bedrock
// advertises its Titan/Cohere embedding models.
func TestGetSupportedProviders_Bedrock_HasEmbeddingModels(t *testing.T) {
	s := blankServer()
	resp, err := s.GetSupportedProviders(tenantCtx("acme"), &tenantv1.GetSupportedProvidersRequest{})
	require.NoError(t, err)

	var bedrock *tenantv1.SupportedProvider
	for _, p := range resp.Providers {
		if p.Type == "bedrock" {
			bedrock = p
			break
		}
	}
	require.NotNil(t, bedrock, "bedrock provider must be present in catalogue")
	assert.NotEmpty(t, bedrock.EmbeddingModels, "bedrock must advertise embedding models")

	names := make([]string, 0, len(bedrock.EmbeddingModels))
	for _, m := range bedrock.EmbeddingModels {
		names = append(names, m.Name)
	}
	assert.Contains(t, names, "amazon.titan-embed-text-v2:0")
	assert.Contains(t, names, "cohere.embed-english-v3")
}

// TestGetSupportedProviders_Anthropic_NoEmbeddingModels verifies that
// Anthropic (chat-only) has no embedding_models entry.
func TestGetSupportedProviders_Anthropic_NoEmbeddingModels(t *testing.T) {
	s := blankServer()
	resp, err := s.GetSupportedProviders(tenantCtx("acme"), &tenantv1.GetSupportedProvidersRequest{})
	require.NoError(t, err)

	for _, p := range resp.Providers {
		if p.Type == "anthropic" {
			assert.Empty(t, p.EmbeddingModels, "anthropic is chat-only and must not advertise embedding models")
			return
		}
	}
	t.Fatal("anthropic provider not found in catalogue")
}

// TestGetSupportedProviders_Voyage_EmbeddingOnly verifies voyage appears in
// the catalogue as an embedding-only provider with no default_models but with
// embedding_models.
func TestGetSupportedProviders_Voyage_EmbeddingOnly(t *testing.T) {
	s := blankServer()
	resp, err := s.GetSupportedProviders(tenantCtx("acme"), &tenantv1.GetSupportedProvidersRequest{})
	require.NoError(t, err)

	var voyage *tenantv1.SupportedProvider
	for _, p := range resp.Providers {
		if p.Type == "voyage" {
			voyage = p
			break
		}
	}
	require.NotNil(t, voyage, "voyage provider must be present in catalogue")
	assert.Empty(t, voyage.DefaultModels, "voyage is embedding-only and must have no chat models")
	assert.NotEmpty(t, voyage.EmbeddingModels, "voyage must advertise embedding models")
}

// TestGetSupportedProviders_ModelDescriptorCapabilities verifies that chat
// models in the catalogue carry CAPABILITY_CHAT on their descriptor.
func TestGetSupportedProviders_ModelDescriptorCapabilities(t *testing.T) {
	s := blankServer()
	resp, err := s.GetSupportedProviders(tenantCtx("acme"), &tenantv1.GetSupportedProvidersRequest{})
	require.NoError(t, err)

	for _, p := range resp.Providers {
		for _, m := range p.DefaultModels {
			// default_models are chat models — they should carry CAPABILITY_CHAT
			// when the catalogue populates capabilities.
			if len(m.Capabilities) > 0 {
				assert.Contains(t, m.Capabilities, tenantv1.Capability_CAPABILITY_CHAT,
					"chat model %q in provider %q must carry CAPABILITY_CHAT", m.Name, p.Type)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// TestProvider embedding probe (gibson#1013)
// ---------------------------------------------------------------------------

// TestTestProvider_ChatOnly_NoEmbeddingProbe verifies that a chat-only
// provider (no CAPABILITY_EMBEDDING) does not run the embedding probe.
func TestTestProvider_ChatOnly_NoEmbeddingProbe(t *testing.T) {
	var embedderCalled bool
	s := blankServer()
	s.WithEmbedderFactory(func(_ embedder.Config) (embedder.Embedder, error) {
		embedderCalled = true
		return embedder.NewMockEmbedder(), nil
	})
	// providerFactory: return a stub that always succeeds health check.
	s.WithProviderFactory(func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return &stubMockProvider{}, nil
	})

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:         "anthropic-chat",
			Type:         "anthropic",
			DefaultModel: "claude-opus-4-7",
			Capabilities: []tenantv1.Capability{tenantv1.Capability_CAPABILITY_CHAT},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, embedderCalled, "embedding probe must NOT run for chat-only provider")
	assert.False(t, resp.EmbeddingOk, "embedding_ok must be false when probe was not run")
	assert.Zero(t, resp.EmbeddingDimension)
}

// TestTestProvider_EmbeddingCapability_ProbeSuccess verifies that when a
// provider declares CAPABILITY_EMBEDDING + default_embedding_model, the
// embedding probe is run and the dimension is returned.
func TestTestProvider_EmbeddingCapability_ProbeSuccess(t *testing.T) { //nolint:dupl // success/failure pair differs only in factory stub and assertions
	s := blankServer()
	s.WithEmbedderFactory(stubSuccessEmbedderFactory)
	s.WithProviderFactory(func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return &stubMockProvider{}, nil
	})

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:                  "openai-dual",
			Type:                  "openai",
			DefaultModel:          "gpt-4o",
			DefaultEmbeddingModel: "text-embedding-3-small",
			Capabilities: []tenantv1.Capability{
				tenantv1.Capability_CAPABILITY_CHAT,
				tenantv1.Capability_CAPABILITY_EMBEDDING,
			},
			Credentials: map[string]string{"api_key": "sk-test"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Ok, "chat probe must succeed")
	assert.True(t, resp.EmbeddingOk, "embedding probe must succeed")
	assert.Positive(t, resp.EmbeddingDimension, "embedding dimension must be reported")
	assert.Empty(t, resp.EmbeddingError)
}

// TestTestProvider_EmbeddingCapability_ProbeFailure verifies that when the
// embedding probe fails for a dual-capability provider, the chat result is
// still returned with ok=true and embedding_ok=false.
func TestTestProvider_EmbeddingCapability_ProbeFailure(t *testing.T) { //nolint:dupl // success/failure pair differs only in factory stub and assertions
	s := blankServer()
	s.WithEmbedderFactory(stubErrorEmbedderFactory)
	s.WithProviderFactory(func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return &stubMockProvider{}, nil
	})

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:                  "openai-dual",
			Type:                  "openai",
			DefaultModel:          "gpt-4o",
			DefaultEmbeddingModel: "text-embedding-3-small",
			Capabilities: []tenantv1.Capability{
				tenantv1.Capability_CAPABILITY_CHAT,
				tenantv1.Capability_CAPABILITY_EMBEDDING,
			},
			Credentials: map[string]string{"api_key": "sk-test"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Chat ok=true (factory returns stub that succeeds); embedding_ok=false.
	assert.True(t, resp.Ok, "ok reflects chat success for dual-capability provider")
	assert.False(t, resp.EmbeddingOk, "embedding_ok must be false when probe fails")
	assert.NotEmpty(t, resp.EmbeddingError, "embedding_error must describe the failure")
	assert.Zero(t, resp.EmbeddingDimension)
}

// TestTestProvider_EmbeddingOnly_ProbeSuccess verifies that voyage (embedding-
// only) runs only the embedding probe and returns ok=true on success.
func TestTestProvider_EmbeddingOnly_ProbeSuccess(t *testing.T) {
	s := blankServer()
	s.WithEmbedderFactory(stubSuccessEmbedderFactory)

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:                  "voyage-embed",
			Type:                  "voyage",
			DefaultEmbeddingModel: "voyage-3",
			Capabilities:          []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
			Credentials:           map[string]string{"api_key": "pa-test"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Ok, "ok must reflect embedding success for embedding-only provider")
	assert.True(t, resp.EmbeddingOk)
	assert.Positive(t, resp.EmbeddingDimension)
}

// TestTestProvider_EmbeddingOnly_ProbeFailure verifies that a failed embedding
// probe returns ok=false for embedding-only providers.
func TestTestProvider_EmbeddingOnly_ProbeFailure(t *testing.T) {
	s := blankServer()
	s.WithEmbedderFactory(stubErrorEmbedderFactory)

	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:                  "voyage-embed",
			Type:                  "voyage",
			DefaultEmbeddingModel: "voyage-3",
			Capabilities:          []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
			Credentials:           map[string]string{"api_key": "pa-bad-key"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Ok, "ok must be false when embedding probe fails for embedding-only provider")
	assert.False(t, resp.EmbeddingOk)
	assert.NotEmpty(t, resp.EmbeddingError)
}

// ---------------------------------------------------------------------------
// ProbeProvider (gibson#1013 — implementation)
// ---------------------------------------------------------------------------

// TestProbeProvider_MissingType_InvalidArgument verifies that an empty type
// returns codes.InvalidArgument.
func TestProbeProvider_MissingType_InvalidArgument(t *testing.T) {
	s := blankServer()
	_, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

// TestProbeProvider_UnknownType_InvalidArgument verifies unknown type rejects.
func TestProbeProvider_UnknownType_InvalidArgument(t *testing.T) {
	s := blankServer()
	_, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type: "notreal",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

// TestProbeProvider_EmbeddingOnly_NoModel_NotOK verifies voyage without a
// model returns ok=false with a clear error.
func TestProbeProvider_EmbeddingOnly_NoModel_NotOK(t *testing.T) {
	s := blankServer()
	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:        "voyage",
		Credentials: map[string]string{"api_key": "pa-test"},
		// no default_embedding_model
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.ErrorMessage, "default_embedding_model")
}

// TestProbeProvider_EmbeddingOnly_Success verifies voyage probe returns
// ok=true + dimension when the factory succeeds.
func TestProbeProvider_EmbeddingOnly_Success(t *testing.T) {
	s := blankServer()
	s.WithEmbedderFactory(stubSuccessEmbedderFactory)

	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:                  "voyage",
		Credentials:           map[string]string{"api_key": "pa-test"},
		DefaultEmbeddingModel: "voyage-3",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Ok)
	assert.Positive(t, resp.EmbeddingDimension)
	assert.Empty(t, resp.ErrorMessage)
}

// TestProbeProvider_EmbeddingOnly_Failure verifies voyage probe returns
// ok=false + error when the factory fails.
func TestProbeProvider_EmbeddingOnly_Failure(t *testing.T) {
	s := blankServer()
	s.WithEmbedderFactory(stubErrorEmbedderFactory)

	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:                  "voyage",
		Credentials:           map[string]string{"api_key": "pa-bad"},
		DefaultEmbeddingModel: "voyage-3",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Ok)
	assert.NotEmpty(t, resp.ErrorMessage)
}

// TestProbeProvider_ChatProvider_Success verifies a chat provider probe
// returns ok=true when the factory + stubMockProvider succeed.
func TestProbeProvider_ChatProvider_Success(t *testing.T) {
	s := blankServer()
	s.WithProviderFactory(func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return &stubMockProvider{}, nil
	})

	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:        "anthropic",
		Credentials: map[string]string{"api_key": "sk-ant-test"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Ok)
	assert.Empty(t, resp.ErrorMessage)
	assert.Zero(t, resp.EmbeddingDimension, "no embedding probe when model is not set")
}

// TestProbeProvider_ChatProvider_WithEmbeddingModel adds an embedding dimension
// to the response when default_embedding_model is supplied.
func TestProbeProvider_ChatProvider_WithEmbeddingModel(t *testing.T) {
	s := blankServer()
	s.WithProviderFactory(func(_ llm.ProviderConfig) (llm.LLMProvider, error) {
		return &stubMockProvider{}, nil
	})
	s.WithEmbedderFactory(stubSuccessEmbedderFactory)

	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{
		Type:                  "openai",
		Credentials:           map[string]string{"api_key": "sk-test"},
		DefaultEmbeddingModel: "text-embedding-3-small",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Ok)
	assert.Positive(t, resp.EmbeddingDimension,
		"embedding dimension must be populated when model + factory succeed")
}

// TestProbeProvider_UnauthenticatedContext_Unauthenticated verifies a missing
// tenant context returns codes.Unauthenticated.
func TestProbeProvider_UnauthenticatedContext_Unauthenticated(t *testing.T) {
	s := blankServer()
	_, err := s.ProbeProvider(context.Background(), &tenantv1.ProbeProviderRequest{
		Type: "openai",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, grpcCode(err))
}
