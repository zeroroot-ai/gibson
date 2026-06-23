package api

// server_provider_config_embedding_test.go — unit tests for the E11 BYO-embedder
// wiring (ADR-0059, gibson#810): the capabilities / default_embedding_model
// fields round-trip through the provider-config translators, embedding-capable
// providers are validated, and the per-tenant embedder resolver gates vector
// features when no embedding provider is configured.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestFromProtoInput_CarriesEmbeddingFields verifies the write-side translator
// threads capabilities + default_embedding_model into the internal input.
func TestFromProtoInput_CarriesEmbeddingFields(t *testing.T) {
	in := &tenantv1.ProviderConfigInput{
		Name:         "openai",
		Type:         "openai",
		DefaultModel: "gpt-4o-mini",
		Capabilities: []tenantv1.Capability{
			tenantv1.Capability_CAPABILITY_CHAT,
			tenantv1.Capability_CAPABILITY_EMBEDDING,
		},
		DefaultEmbeddingModel: "text-embedding-3-small",
	}
	got := fromProtoInput(in)
	assert.Equal(t, []string{"chat", "embedding"}, got.Capabilities)
	assert.Equal(t, "text-embedding-3-small", got.DefaultEmbeddingModel)
}

// TestToProtoProviderRecord_CarriesEmbeddingFields verifies the read-side
// translator surfaces capabilities + default_embedding_model back on the wire.
func TestToProtoProviderRecord_CarriesEmbeddingFields(t *testing.T) {
	cfg := &providerconfig.ProviderConfig{
		Name:                  "openai",
		Type:                  llm.ProviderOpenAI,
		Capabilities:          []string{"chat", "embedding"},
		DefaultEmbeddingModel: "text-embedding-3-small",
	}
	rec := toProtoProviderRecord(cfg)
	require.NotNil(t, rec)
	assert.Equal(t, []tenantv1.Capability{
		tenantv1.Capability_CAPABILITY_CHAT,
		tenantv1.Capability_CAPABILITY_EMBEDDING,
	}, rec.Capabilities)
	assert.Equal(t, "text-embedding-3-small", rec.DefaultEmbeddingModel)
}

// TestCreateProvider_RoundTripsEmbeddingFields verifies the fields survive the
// Create handler end-to-end (proto → store input → proto record).
func TestCreateProvider_RoundTripsEmbeddingFields(t *testing.T) {
	cfg := &providerconfig.ProviderConfig{
		Name:                  "openai-embed",
		Type:                  llm.ProviderOpenAI,
		Enabled:               true,
		Capabilities:          []string{"chat", "embedding"},
		DefaultEmbeddingModel: "text-embedding-3-small",
	}
	store := &mockProviderStore{createOut: cfg}
	s := serverWithStore(store)

	resp, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:                  "openai-embed",
			Type:                  "openai",
			DefaultModel:          "gpt-4o-mini",
			Capabilities:          []tenantv1.Capability{tenantv1.Capability_CAPABILITY_CHAT, tenantv1.Capability_CAPABILITY_EMBEDDING},
			DefaultEmbeddingModel: "text-embedding-3-small",
			Credentials:           map[string]string{"api_key": "sk-test-key"},
		},
	})
	require.NoError(t, err)

	// The store received the embedding fields.
	require.NotNil(t, store.capturedCreateInput)
	assert.Equal(t, []string{"chat", "embedding"}, store.capturedCreateInput.Capabilities)
	assert.Equal(t, "text-embedding-3-small", store.capturedCreateInput.DefaultEmbeddingModel)

	// The response surfaces them back.
	assert.Equal(t, "text-embedding-3-small", resp.Provider.DefaultEmbeddingModel)
	assert.Contains(t, resp.Provider.Capabilities, tenantv1.Capability_CAPABILITY_EMBEDDING)
}

// TestCreateProvider_EmbeddingWithoutModel_InvalidArgument verifies the
// onboarding-quality validation: an embedding-capable provider must declare a
// default_embedding_model.
func TestCreateProvider_EmbeddingWithoutModel_InvalidArgument(t *testing.T) {
	s := serverWithStore(&mockProviderStore{})
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:         "openai",
			Type:         "openai",
			Capabilities: []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
			// no DefaultEmbeddingModel
		},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(err))
}

// TestCreateProvider_EmbeddingUnknownModel_InvalidArgument verifies that an
// embedding model with no known vector dimension is rejected at write time — a
// wrong dimension would silently fail RediSearch whole-document indexing.
func TestCreateProvider_EmbeddingUnknownModel_InvalidArgument(t *testing.T) {
	s := serverWithStore(&mockProviderStore{})
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:                  "mystery",
			Type:                  "openai",
			Capabilities:          []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
			DefaultEmbeddingModel: "no-such-embedding-model-xyz",
		},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(err))
}

// TestCreateProvider_ChatOnly_NoEmbeddingValidation verifies a chat-only
// provider (the legacy default) is unaffected by the embedding validation.
func TestCreateProvider_ChatOnly_NoEmbeddingValidation(t *testing.T) {
	cfg := fakeProviderRecord("anthropic")
	store := &mockProviderStore{createOut: cfg}
	s := serverWithStore(store)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:         "anthropic",
			Type:         "anthropic",
			DefaultModel: "claude-3-5-sonnet",
			Capabilities: []tenantv1.Capability{tenantv1.Capability_CAPABILITY_CHAT},
		},
	})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ResolveTenantEmbedder gate
// ---------------------------------------------------------------------------

type stubEmbedderResolver struct {
	emb           embedder.Embedder
	err           error
	invalidatedAt []string
}

func (s *stubEmbedderResolver) Resolve(_ context.Context, _ string) (embedder.Embedder, error) {
	return s.emb, s.err
}

func (s *stubEmbedderResolver) Invalidate(tenantID string) {
	s.invalidatedAt = append(s.invalidatedAt, tenantID)
}

// TestResolveTenantEmbedder_NilResolver_Gates verifies a daemon booted without
// the resolver gates gracefully (no panic) with the onboarding error.
func TestResolveTenantEmbedder_NilResolver_Gates(t *testing.T) {
	s := blankServer()
	emb, err := s.ResolveTenantEmbedder(context.Background(), "acme")
	require.Error(t, err)
	assert.Nil(t, emb)
	assert.ErrorIs(t, err, embedder.ErrNoEmbeddingProvider())
}

// TestResolveTenantEmbedder_GateError_PassesThrough verifies the resolver's gate
// error is surfaced verbatim.
func TestResolveTenantEmbedder_GateError_PassesThrough(t *testing.T) {
	s := blankServer()
	s.WithEmbedderResolver(&stubEmbedderResolver{err: embedder.ErrNoEmbeddingProvider()})
	_, err := s.ResolveTenantEmbedder(context.Background(), "acme")
	require.Error(t, err)
	assert.ErrorIs(t, err, embedder.ErrNoEmbeddingProvider())
}

// TestResolveTenantEmbedder_Configured_ReturnsEmbedder verifies the configured
// path returns the tenant's embedder.
func TestResolveTenantEmbedder_Configured_ReturnsEmbedder(t *testing.T) {
	want := embedder.NewMockEmbedder()
	s := blankServer()
	s.WithEmbedderResolver(&stubEmbedderResolver{emb: want})
	got, err := s.ResolveTenantEmbedder(context.Background(), "acme")
	require.NoError(t, err)
	assert.Same(t, want, got)
}

// TestCreateProvider_InvalidatesEmbedderCache verifies a provider mutation drops
// the per-tenant embedder cache so a newly-configured provider is picked up.
func TestCreateProvider_InvalidatesEmbedderCache(t *testing.T) {
	stub := &stubEmbedderResolver{}
	s := serverWithStore(&mockProviderStore{createOut: fakeProviderRecord("openai")})
	s.WithEmbedderResolver(stub)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{Name: "openai", Type: "openai"},
	})
	require.NoError(t, err)
	assert.Contains(t, stub.invalidatedAt, "acme")
}
