// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"log/slog"
	"strings"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// isTransientResolveErr reports whether a credential-resolution failure is a
// transient backend condition (secrets broker down / circuit open) rather than
// a permanent one (bad credential, missing key). The secrets Service maps
// ErrUnavailable to gRPC codes.Unavailable; the raw sentinel string survives in
// the message, so both are checked. A transient failure must NOT be cached —
// caching an incomplete Set built during a broker blip is what froze a passing
// outage into a permanent "provider not found".
func isTransientResolveErr(err error) bool {
	if err == nil {
		return false
	}
	if status.Code(err) == codes.Unavailable {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unavailable") || strings.Contains(msg, "circuit open")
}

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
	// Skipped records the providers that ARE configured for the tenant but
	// could not be built — keyed by provider name, valued by the reason
	// (credential unreadable, factory failed). Downstream surfaces this so a
	// configured-but-broken provider reads as "provider X unavailable: <cause>"
	// instead of the misleading "provider not found" the empty registry yields.
	Skipped map[string]error

	// retryableIncomplete is set when at least one provider was skipped for a
	// TRANSIENT reason (broker unavailable / circuit open). Such a Set is a
	// snapshot of a temporary failure and must not be cached — the next Resolve
	// rebuilds it, picking the provider up once the broker recovers.
	retryableIncomplete bool
}

// Resolver builds and caches a per-tenant provider Set.
type Resolver struct {
	store   Store
	factory ProviderFactory
	// allowPrivate mirrors security.allow_private_llm_endpoints. False (the
	// secure default) keeps the connect-time SSRF egress guard on for every
	// provider built from a tenant's stored base_url.
	allowPrivate bool

	// log records WHY a configured provider was skipped (credential unreadable,
	// factory failed). Never nil after NewResolver. Silently dropping the reason
	// is what turned a missing-credential into a phantom "provider not found".
	log *slog.Logger

	mu    sync.RWMutex
	cache map[string]*Set
}

// NewResolver constructs a Resolver over the given store and provider factory.
// allowPrivate comes from security.allow_private_llm_endpoints; pass false
// unless the operator has opted into private/in-cluster model endpoints. A nil
// logger falls back to slog.Default().
func NewResolver(store Store, factory ProviderFactory, allowPrivate bool, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	return &Resolver{store: store, factory: factory, allowPrivate: allowPrivate, log: log, cache: make(map[string]*Set)}
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

	// Do NOT cache a Set left incomplete by a transient broker failure. Caching
	// it would freeze a momentary outage into a permanent "provider not found"
	// until something else invalidated the tenant — which is exactly the bug
	// this guards. The caller still gets the (partial) Set for this call; the
	// next Resolve rebuilds and picks the provider up once the broker recovers.
	if set.retryableIncomplete {
		r.log.WarnContext(ctx, "tenantprovider: not caching provider set — incomplete due to a transient broker failure; will retry on next resolve",
			"tenant", tenantID, "skipped", len(set.Skipped))
		return set, nil
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
	set := &Set{Registry: registry, Skipped: make(map[string]error)}

	for _, cfg := range configs {
		if cfg == nil || !cfg.Enabled {
			continue
		}
		dec, err := r.store.Resolve(ctx, tenantID, cfg.Name)
		if err != nil || dec == nil {
			// A provider we can't decrypt is skipped rather than failing the
			// whole tenant set — but the reason is RECORDED and LOGGED, never
			// swallowed. A silent skip here is what surfaced downstream as the
			// misleading "provider not found: <name>" (the empty-registry miss)
			// when the real fault was an unreadable credential (e.g. the
			// secrets broker being down or the secret never persisting).
			reason := fmt.Errorf("credential unreadable: %w", err)
			set.Skipped[cfg.Name] = reason
			if isTransientResolveErr(err) {
				set.retryableIncomplete = true
			}
			r.log.WarnContext(ctx, "tenantprovider: provider configured but skipped — credential could not be resolved",
				"tenant", tenantID, "provider", cfg.Name, "transient", isTransientResolveErr(err), "error", err)
			continue
		}
		provider, err := r.factory(decryptedToLLMConfig(dec, r.allowPrivate))
		// dec.Credentials must not outlive this iteration.
		if err != nil || provider == nil {
			reason := fmt.Errorf("provider build failed: %w", err)
			set.Skipped[cfg.Name] = reason
			r.log.WarnContext(ctx, "tenantprovider: provider configured but skipped — factory could not build it",
				"tenant", tenantID, "provider", cfg.Name, "error", err)
			continue
		}
		if regErr := registry.RegisterProvider(provider); regErr != nil {
			set.Skipped[cfg.Name] = fmt.Errorf("registration failed: %w", regErr)
			r.log.WarnContext(ctx, "tenantprovider: provider built but registration failed",
				"tenant", tenantID, "provider", cfg.Name, "error", regErr)
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
func decryptedToLLMConfig(dec *providerconfig.DecryptedConfig, allowPrivate bool) llm.ProviderConfig {
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
		// base_url is tenant-supplied: keep the connect-time SSRF egress guard
		// on unless the operator opted out.
		AllowPrivateEndpoint: allowPrivate,
	}
}
