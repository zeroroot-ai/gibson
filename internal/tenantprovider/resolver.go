// Package tenantprovider resolves a tenant's configured LLM providers into a
// live, per-tenant llm.LLMRegistry — the source of truth for mission/agent slot
// resolution. It replaces the legacy global, startup-only registry (a relic of
// the single-tenant on-prem design) with per-tenant scoping sourced from the
// broker-backed providerconfig store.
//
// SECURITY: decrypted credentials obtained from Store.Resolve are used only to
// construct a provider and never logged, persisted, or cached as raw maps. The
// constructed providers (which hold their key in process memory, as the legacy
// registry always did) are cached per tenant; the plaintext credential map is
// not.
package tenantprovider

import (
	"context"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/providerconfig"
)

// Store is the narrow per-tenant provider surface the resolver needs. It is
// satisfied by providerconfig.ProviderConfigStore.
type Store interface {
	List(ctx context.Context, tenantID string) ([]*providerconfig.ProviderConfig, error)
	Resolve(ctx context.Context, tenantID, name string) (*providerconfig.DecryptedConfig, error)
}

// ProviderFactory builds a live provider from a decrypted config. Satisfied by
// providers.NewProvider.
type ProviderFactory func(cfg llm.ProviderConfig) (llm.LLMProvider, error)

// Set is a tenant's resolved provider set: a registry holding the tenant's
// providers plus the registry name of the tenant's default provider ("" if
// none).
type Set struct {
	Registry    llm.LLMRegistry
	DefaultName string
}

// Resolver builds and caches a per-tenant provider Set.
type Resolver struct {
	store   Store
	factory ProviderFactory

	mu    sync.RWMutex
	cache map[string]*Set
}

// NewResolver constructs a Resolver over the given store and provider factory.
func NewResolver(store Store, factory ProviderFactory) *Resolver {
	return &Resolver{store: store, factory: factory, cache: make(map[string]*Set)}
}

// Resolve returns the tenant's provider Set, building and caching it on first
// use. An empty tenant is an error. A tenant with no configured providers
// yields a Set with an empty registry (callers decide how to surface that).
func (r *Resolver) Resolve(ctx context.Context, tenantID string) (*Set, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantprovider: tenant is required")
	}

	r.mu.RLock()
	if set, ok := r.cache[tenantID]; ok {
		r.mu.RUnlock()
		return set, nil
	}
	r.mu.RUnlock()

	set, err := r.build(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.cache[tenantID] = set
	r.mu.Unlock()
	return set, nil
}

// Invalidate drops the cached Set for a tenant. Call after any provider-config
// mutation (create/update/delete/set-default) so the next Resolve rebuilds.
func (r *Resolver) Invalidate(tenantID string) {
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
}

func (r *Resolver) build(ctx context.Context, tenantID string) (*Set, error) {
	configs, err := r.store.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantprovider: list providers for tenant: %w", err)
	}

	registry := llm.NewLLMRegistry()
	set := &Set{Registry: registry}

	for _, cfg := range configs {
		if cfg == nil || !cfg.Enabled {
			continue
		}
		dec, err := r.store.Resolve(ctx, tenantID, cfg.Name)
		if err != nil || dec == nil {
			// A provider we can't decrypt is skipped rather than failing the
			// whole tenant set; the slot will fail to resolve if nothing else
			// is available, surfacing the real problem.
			continue
		}
		provider, err := r.factory(decryptedToLLMConfig(dec))
		// dec.Credentials must not outlive this iteration.
		if err != nil || provider == nil {
			continue
		}
		if regErr := registry.RegisterProvider(provider); regErr != nil {
			continue
		}
		if cfg.IsDefault {
			set.DefaultName = provider.Name()
		}
	}

	return set, nil
}

// decryptedToLLMConfig mirrors the ExecuteLLM translation: api_key/base_url are
// typed fields, all other credential keys flow through Extra.
func decryptedToLLMConfig(dec *providerconfig.DecryptedConfig) llm.ProviderConfig {
	extra := make(map[string]string)
	for k, v := range dec.Credentials {
		switch k {
		case "api_key", "base_url":
		default:
			extra[k] = v
		}
	}
	return llm.ProviderConfig{
		Type:         dec.Type,
		APIKey:       dec.Credentials["api_key"],
		BaseURL:      dec.Credentials["base_url"],
		DefaultModel: dec.DefaultModel,
		Extra:        extra,
	}
}
