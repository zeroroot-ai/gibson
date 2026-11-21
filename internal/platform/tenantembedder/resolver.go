// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package tenantembedder resolves the embedding provider of a tenant into a
// per-tenant embedder.Embedder. It is the one source of embeddings for vector
// recall, GraphRAG, belief-RAG and finding classification (ADR-0059,
// gibson#810).
//
// The resolver reads the provider records of the tenant from the providerconfig
// store and builds the embedder on first use. It caches one embedder for each
// tenant. The embedder is not a startup singleton of the daemon, because the
// model, and so the vector dimension, belongs to the tenant. A tenant with no
// embedding provider hits the onboarding gate: Resolve returns
// embedder.ErrNoEmbeddingProvider, and the caller asks the user to configure a
// provider. No bundled model is a fallback. MockEmbedder is for tests only.
//
// The resolver and the embedder hold no credential and no endpoint. Each
// embedding call goes to the model gateway, which holds both (ADR-0172).
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
}

// Factory builds an embedder from a resolved config. Defaults to
// embedder.NewFromProvider; injectable so tests can stub the upstream.
type Factory func(cfg embedder.Config) (embedder.Embedder, error)

// Resolver builds and caches a per-tenant embedder.
type Resolver struct {
	store   Store
	factory Factory
	// gateway sends each embeddings call to the model gateway (gibson#1393).
	gateway embedder.Gateway

	mu    sync.RWMutex
	cache map[string]embedder.Embedder
}

// NewResolver constructs a Resolver over the given store. The gateway is the
// model client of the daemon: the embedder holds no credential and no endpoint.
func NewResolver(store Store, gateway embedder.Gateway) *Resolver {
	return &Resolver{
		store:   store,
		factory: embedder.NewFromProvider,
		gateway: gateway,
		cache:   make(map[string]embedder.Embedder),
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

	emb, err := r.factory(embedder.Config{
		Kind:     embedder.Kind(string(cfg.Type)),
		Model:    cfg.DefaultEmbeddingModel,
		Tenant:   tenantID,
		Provider: cfg.Name,
		Gateway:  r.gateway,
	})
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
