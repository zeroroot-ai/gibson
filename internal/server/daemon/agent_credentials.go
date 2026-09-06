// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// providerCredentialSource backs harness.CredentialSource with the per-tenant
// provider store: a sandboxed platform agent that needs, say, an Anthropic key
// gets the DISPATCHING tenant's own (gibson#1621 decision 12). Selection: the
// tenant's default provider of that type when one is default, else the only
// enabled one. Two enabled non-default providers of one type is ambiguous and
// is refused rather than guessed.
type providerCredentialSource struct {
	// store is the resolved provider store. Tests set it directly.
	store providerconfig.ProviderConfigStore
	// resolve builds the store on first use. The harness factory is built
	// before the data-plane pool and the broker stack exist (daemon Start:
	// newInfrastructure precedes the pool and initBrokerStack), so wiring the
	// store at construction always caught nil and every catalog agent that
	// declares tenant credentials was refused with "no credential source is
	// wired". Resolving lazily binds to whatever the daemon has at dispatch.
	resolve func() (providerconfig.ProviderConfigStore, error)
	mu      sync.Mutex
}

// current returns the store, building it on first use when only resolve is
// set. A store that cannot be built yet is an error the caller surfaces as
// a refused dispatch, never a silent degrade.
func (s *providerCredentialSource) current() (providerconfig.ProviderConfigStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		return s.store, nil
	}
	if s.resolve == nil {
		return nil, errors.New("no provider store and no resolver")
	}
	store, err := s.resolve()
	if err != nil {
		return nil, err
	}
	s.store = store
	return store, nil
}

var _ harness.CredentialSource = (*providerCredentialSource)(nil)

func (s *providerCredentialSource) ResolveProviderCredential(ctx context.Context, tenant, provider, key string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: provider store unavailable", harness.ErrTenantCredentialMissing)
	}
	store, err := s.current()
	if err != nil {
		return "", fmt.Errorf("%w: %w", harness.ErrTenantCredentialMissing, err)
	}
	configs, err := store.List(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("list tenant providers: %w", err)
	}
	candidates := make([]*providerconfig.ProviderConfig, 0, len(configs))
	for _, c := range configs {
		if c == nil || !c.Enabled || c.Type != llm.ProviderType(provider) {
			continue
		}
		if c.IsDefault {
			candidates = []*providerconfig.ProviderConfig{c}
			break
		}
		candidates = append(candidates, c)
	}
	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("%w: tenant %q has no enabled %q provider; add one under Settings, Providers", harness.ErrTenantCredentialMissing, tenant, provider)
	case 1:
	default:
		return "", fmt.Errorf("%w: tenant %q has %d enabled %q providers and none is default", harness.ErrTenantCredentialMissing, tenant, len(candidates), provider)
	}
	dec, err := s.store.Resolve(ctx, tenant, candidates[0].Name)
	if err != nil {
		return "", fmt.Errorf("resolve provider %q: %w", candidates[0].Name, err)
	}
	value := dec.Credentials[key]
	if value == "" {
		return "", fmt.Errorf("%w: provider %q carries no %q", harness.ErrTenantCredentialMissing, candidates[0].Name, key)
	}
	return value, nil
}

// tenantCredentialResolver binds the provider store for catalog-agent
// credentials at first dispatch. The harness factory is built before the
// data-plane pool and the broker stack are up (daemon Start), so the store
// cannot be built at factory time; until both exist a dispatch that needs
// tenant credentials is refused, loudly.
func (d *daemonImpl) tenantCredentialResolver() func() (providerconfig.ProviderConfigStore, error) {
	return func() (providerconfig.ProviderConfigStore, error) {
		if d.pool != nil && d.secretsService != nil {
			return providerconfig.NewBrokerBackedStore(d.pool, d.secretsService), nil
		}
		return nil, errors.New("provider store not initialized: the data-plane pool or the broker stack is not up")
	}
}
