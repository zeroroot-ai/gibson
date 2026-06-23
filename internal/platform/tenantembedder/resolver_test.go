package tenantembedder

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// fakeStore satisfies the resolver Store with deterministic, in-memory data.
type fakeStore struct {
	configs    []*providerconfig.ProviderConfig
	listErr    error
	decrypted  map[string]*providerconfig.DecryptedConfig
	resolveErr error
}

func (f *fakeStore) List(_ context.Context, _ string) ([]*providerconfig.ProviderConfig, error) {
	return f.configs, f.listErr
}

func (f *fakeStore) Resolve(_ context.Context, _, name string) (*providerconfig.DecryptedConfig, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return f.decrypted[name], nil
}

func embeddingProvider(name, model string, isDefault, enabled bool) *providerconfig.ProviderConfig {
	return &providerconfig.ProviderConfig{
		Name:                  name,
		Type:                  llm.ProviderOpenAI,
		Enabled:               enabled,
		IsDefault:             isDefault,
		Capabilities:          []string{providerconfig.CapabilityChat, providerconfig.CapabilityEmbedding},
		DefaultEmbeddingModel: model,
	}
}

func chatOnlyProvider(name string) *providerconfig.ProviderConfig {
	return &providerconfig.ProviderConfig{
		Name:         name,
		Type:         llm.ProviderAnthropic,
		Enabled:      true,
		Capabilities: []string{providerconfig.CapabilityChat},
	}
}

// TestResolve_NoEmbeddingProvider_Gates verifies the onboarding gate: a tenant
// with only chat-capable providers (or none) gets the gate error, not a mock.
func TestResolve_NoEmbeddingProvider_Gates(t *testing.T) {
	cases := map[string]*fakeStore{
		"no providers at all": {configs: nil},
		"chat-only provider":  {configs: []*providerconfig.ProviderConfig{chatOnlyProvider("anthropic")}},
		"embedding provider disabled": {
			configs: []*providerconfig.ProviderConfig{embeddingProvider("openai", "text-embedding-3-small", true, false)},
		},
	}
	for name, store := range cases {
		t.Run(name, func(t *testing.T) {
			r := NewResolver(store, false)
			emb, err := r.Resolve(context.Background(), "acme")
			require.Error(t, err)
			assert.Nil(t, emb)
			var gerr *types.GibsonError
			require.True(t, errors.As(err, &gerr))
			assert.Equal(t, embedder.ErrCodeNoEmbeddingProvider, gerr.Code)
		})
	}
}

// TestResolve_Configured_BuildsAtRightDimension verifies a tenant with an
// embedding provider gets an embedder whose dimension matches the configured
// model (#807's per-model dimension).
func TestResolve_Configured_BuildsAtRightDimension(t *testing.T) {
	cfg := embeddingProvider("openai", "text-embedding-3-small", true, true)
	store := &fakeStore{
		configs: []*providerconfig.ProviderConfig{cfg},
		decrypted: map[string]*providerconfig.DecryptedConfig{
			"openai": {
				ProviderConfig: *cfg,
				Credentials:    map[string]string{"api_key": "sk-test"},
			},
		},
	}
	r := NewResolver(store, false)
	emb, err := r.Resolve(context.Background(), "acme")
	require.NoError(t, err)
	require.NotNil(t, emb)
	assert.Equal(t, "text-embedding-3-small", emb.Model())
	assert.Equal(t, 1536, emb.Dimensions(), "index dimension must match the configured embedding model")
}

// TestResolve_EmptyTenant_Error verifies an empty tenant is rejected.
func TestResolve_EmptyTenant_Error(t *testing.T) {
	r := NewResolver(&fakeStore{}, false)
	_, err := r.Resolve(context.Background(), "")
	require.Error(t, err)
}

// TestResolve_CachesAndInvalidates verifies the embedder is built once and
// cached, and that Invalidate forces a rebuild (e.g. after a model switch).
func TestResolve_CachesAndInvalidates(t *testing.T) {
	cfg := embeddingProvider("openai", "text-embedding-3-small", true, true)
	dec := &providerconfig.DecryptedConfig{ProviderConfig: *cfg, Credentials: map[string]string{"api_key": "sk-test"}}
	store := &fakeStore{
		configs:   []*providerconfig.ProviderConfig{cfg},
		decrypted: map[string]*providerconfig.DecryptedConfig{"openai": dec},
	}

	var builds int
	r := NewResolver(store, false).WithFactory(func(c embedder.Config) (embedder.Embedder, error) {
		builds++
		return embedder.NewFromProvider(c)
	})

	_, err := r.Resolve(context.Background(), "acme")
	require.NoError(t, err)
	_, err = r.Resolve(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 1, builds, "embedder must be cached per tenant")

	r.Invalidate("acme")
	_, err = r.Resolve(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 2, builds, "Invalidate must force a rebuild")
}

// TestResolve_GateNotCached verifies the gate error is not cached: a tenant that
// configures a provider after an initial gated call resolves on the next call.
func TestResolve_GateNotCached(t *testing.T) {
	store := &fakeStore{configs: nil}
	r := NewResolver(store, false)

	_, err := r.Resolve(context.Background(), "acme")
	require.Error(t, err)

	// Tenant now configures an embedding provider.
	cfg := embeddingProvider("openai", "text-embedding-3-small", true, true)
	store.configs = []*providerconfig.ProviderConfig{cfg}
	store.decrypted = map[string]*providerconfig.DecryptedConfig{
		"openai": {ProviderConfig: *cfg, Credentials: map[string]string{"api_key": "sk-test"}},
	}
	emb, err := r.Resolve(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, 1536, emb.Dimensions())
}

// TestSelectEmbeddingProvider_PrefersDefault verifies provider selection prefers
// the default embedding provider, else the first enabled embedding-capable one.
func TestSelectEmbeddingProvider_PrefersDefault(t *testing.T) {
	first := embeddingProvider("voyage", "voyage-3", false, true)
	def := embeddingProvider("openai", "text-embedding-3-small", true, true)
	got := selectEmbeddingProvider([]*providerconfig.ProviderConfig{first, def})
	require.NotNil(t, got)
	assert.Equal(t, "openai", got.Name, "default embedding provider wins")

	// No default → first enabled embedding-capable provider.
	got = selectEmbeddingProvider([]*providerconfig.ProviderConfig{first})
	require.NotNil(t, got)
	assert.Equal(t, "voyage", got.Name)
}
