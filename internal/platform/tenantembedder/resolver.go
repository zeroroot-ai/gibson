// Package tenantembedder resolves a tenant's configured embedding provider into
// a live, per-tenant embedder.Embedder — the source of truth for vector recall,
// GraphRAG, belief-RAG and finding-classification embedding (E11 BYO-embedder,
// ADR-0059, gibson#810).
//
// It is the embedding analogue of tenantprovider.Resolver (which scopes the LLM
// chat registry per tenant): each tenant's embedder is built lazily from the
// broker-backed providerconfig store and cached. The embedder is NOT a daemon
// startup singleton — it cannot be, because the model (and therefore the vector
// dimension) is per-tenant. A tenant with no embedding-capable provider hits the
// onboarding gate: Resolve returns embedder.ErrNoEmbeddingProvider so callers
// surface a graceful "configure an embedding provider" prompt rather than
// falling back to a bundled mock (the bundled MockEmbedder is retained strictly
// for tests/fixtures).
//
// SECURITY: decrypted credentials obtained from Store.Resolve are used only to
// construct the embedder and never logged, persisted, or cached as raw maps. The
// constructed embedder (which holds its key in process memory) is cached per
// tenant; the plaintext credential map is not.
package tenantembedder

import (
	"context"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// Store is the narrow per-tenant provider surface the resolver needs. It is
// satisfied by providerconfig.ProviderConfigStore.
type Store interface {
	List(ctx context.Context, tenantID string) ([]*providerconfig.ProviderConfig, error)
	Resolve(ctx context.Context, tenantID, name string) (*providerconfig.DecryptedConfig, error)
}

// Factory builds an embedder from a resolved config. Defaults to
// embedder.NewFromProvider; injectable so tests can stub the upstream.
type Factory func(cfg embedder.Config) (embedder.Embedder, error)

// Resolver builds and caches a per-tenant embedder.
type Resolver struct {
	store   Store
	factory Factory
	// allowPrivateEndpoint mirrors security.allow_private_llm_endpoints: when
	// true, an operator-run in-cluster/air-gapped embedder endpoint resolving to
	// a private address is permitted.
	allowPrivateEndpoint bool

	mu    sync.RWMutex
	cache map[string]embedder.Embedder
}

// NewResolver constructs a Resolver over the given store. allowPrivate is the
// security.allow_private_llm_endpoints toggle, forwarded to the embedder factory
// so self-hosted endpoints can opt out of the SSRF guard.
func NewResolver(store Store, allowPrivate bool) *Resolver {
	return &Resolver{
		store:                store,
		factory:              embedder.NewFromProvider,
		allowPrivateEndpoint: allowPrivate,
		cache:                make(map[string]embedder.Embedder),
	}
}

// WithFactory overrides the embedder factory (tests).
func (r *Resolver) WithFactory(f Factory) *Resolver {
	r.factory = f
	return r
}

// Resolve returns the tenant's embedder, building and caching it on first use.
// An empty tenant is an error. A tenant with no embedding-capable provider
// returns embedder.ErrNoEmbeddingProvider — the onboarding gate — which callers
// surface verbatim to the user. The error is NOT cached, so a tenant that later
// configures a provider resolves successfully on the next call.
func (r *Resolver) Resolve(ctx context.Context, tenantID string) (embedder.Embedder, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantembedder: tenant is required")
	}

	r.mu.RLock()
	if emb, ok := r.cache[tenantID]; ok {
		r.mu.RUnlock()
		return emb, nil
	}
	r.mu.RUnlock()

	emb, err := r.build(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.cache[tenantID] = emb
	r.mu.Unlock()
	return emb, nil
}

// Invalidate drops the cached embedder for a tenant. Call after any
// provider-config mutation (create/update/delete/set-default) so the next
// Resolve rebuilds — e.g. after a tenant switches embedding models, the
// re-embed job (gibson#809) runs and subsequent recalls use the new dimension.
func (r *Resolver) Invalidate(tenantID string) {
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
}

func (r *Resolver) build(ctx context.Context, tenantID string) (embedder.Embedder, error) {
	configs, err := r.store.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantembedder: list providers for tenant: %w", err)
	}

	cfg := selectEmbeddingProvider(configs)
	if cfg == nil {
		// Onboarding gate: no embedding-capable provider configured.
		return nil, embedder.ErrNoEmbeddingProvider()
	}

	dec, err := r.store.Resolve(ctx, tenantID, cfg.Name)
	if err != nil || dec == nil {
		return nil, fmt.Errorf("tenantembedder: resolve embedding provider %q: %w", cfg.Name, err)
	}

	emb, err := r.factory(r.decryptedToEmbedderConfig(dec))
	// dec.Credentials must not outlive this function.
	if err != nil {
		return nil, fmt.Errorf("tenantembedder: build embedder for provider %q: %w", cfg.Name, err)
	}
	return emb, nil
}

// selectEmbeddingProvider picks the tenant's embedding provider. Preference:
// the default provider if it serves embeddings, else the first enabled
// embedding-capable provider (deterministic — providerconfig.List orders by
// name). Returns nil when no enabled provider declares the embedding capability.
func selectEmbeddingProvider(configs []*providerconfig.ProviderConfig) *providerconfig.ProviderConfig {
	var fallback *providerconfig.ProviderConfig
	for _, cfg := range configs {
		if cfg == nil || !cfg.Enabled || !cfg.ServesEmbedding() {
			continue
		}
		if cfg.IsDefault {
			return cfg
		}
		if fallback == nil {
			fallback = cfg
		}
	}
	return fallback
}

// decryptedToEmbedderConfig maps a decrypted provider config to the embedder
// factory Config. The Kind is the provider type string (the embedder factory
// normalizes case); the Model is default_embedding_model (NOT default_model, the
// chat model); api_key/base_url/region map to typed fields, and every other
// credential key flows through Extra (mirroring tenantprovider's translation).
func (r *Resolver) decryptedToEmbedderConfig(dec *providerconfig.DecryptedConfig) embedder.Config {
	extra := make(map[string]string)
	for k, v := range dec.Credentials {
		switch k {
		case "api_key", "base_url", "region":
		default:
			extra[k] = v
		}
	}
	return embedder.Config{
		Kind:                 embedder.Kind(string(dec.Type)),
		Model:                dec.DefaultEmbeddingModel,
		APIKey:               dec.Credentials["api_key"],
		BaseURL:              dec.Credentials["base_url"],
		Region:               dec.Credentials["region"],
		Extra:                extra,
		AllowPrivateEndpoint: r.allowPrivateEndpoint,
	}
}
