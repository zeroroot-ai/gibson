package daemon

// pool_providerconfig.go — Phase D: pool-backed providerconfig store.
//
// PoolProviderConfigStore wraps the per-tenant data-plane Pool to implement
// the server_provider_config.providerConfigStoreIface (which takes a tenantID
// string parameter on every call). Each method acquires a Conn for the named
// tenant, constructs a per-call providerconfig.NewPostgresStore from
// conn.Postgres + conn.KEK, delegates, and releases the Conn.
//
// This eliminates the credentialPGPool bridge that previously supplied a shared
// Postgres pool for providerconfig storage.

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/providerconfig"
	"github.com/zero-day-ai/sdk/auth"
)

// PoolProviderConfigStore implements providerConfigStoreIface by routing each
// call to the per-tenant Postgres database via the data-plane Pool.
type PoolProviderConfigStore struct {
	pool datapool.Pool
}

// NewPoolProviderConfigStore constructs a PoolProviderConfigStore backed by pool.
func NewPoolProviderConfigStore(pool datapool.Pool) *PoolProviderConfigStore {
	return &PoolProviderConfigStore{pool: pool}
}

// acquireStore acquires a Conn for tenantID and constructs a per-call
// ProviderConfigStore from it. The caller must call release() when done.
func (s *PoolProviderConfigStore) acquireStore(ctx context.Context, tenantIDStr string) (providerconfig.ProviderConfigStore, func(), error) {
	tid, err := auth.NewTenantID(tenantIDStr)
	if err != nil {
		return nil, nil, fmt.Errorf("pool providerconfig: invalid tenant %q: %w", tenantIDStr, err)
	}

	conn, err := s.pool.For(ctx, tid)
	if err != nil {
		return nil, nil, fmt.Errorf("pool providerconfig: acquire conn for tenant %s: %w", tenantIDStr, err)
	}

	store, storeErr := providerconfig.NewPostgresStore(conn.Postgres, conn.KEK)
	if storeErr != nil {
		conn.Release()
		return nil, nil, fmt.Errorf("pool providerconfig: build store for tenant %s: %w", tenantIDStr, storeErr)
	}

	return store, conn.Release, nil
}

// List lists all provider configs for the tenant.
func (s *PoolProviderConfigStore) List(ctx context.Context, tenantID string) ([]*providerconfig.ProviderConfig, error) {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	return store.List(ctx, tenantID)
}

// Get retrieves a named provider config for the tenant.
func (s *PoolProviderConfigStore) Get(ctx context.Context, tenantID string, name string) (*providerconfig.ProviderConfig, error) {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	return store.Get(ctx, tenantID, name)
}

// Create creates a new provider config for the tenant.
func (s *PoolProviderConfigStore) Create(ctx context.Context, tenantID string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error) {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	return store.Create(ctx, tenantID, input)
}

// Update modifies an existing provider config for the tenant.
func (s *PoolProviderConfigStore) Update(ctx context.Context, tenantID string, name string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error) {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	return store.Update(ctx, tenantID, name, input)
}

// Delete removes a provider config for the tenant.
func (s *PoolProviderConfigStore) Delete(ctx context.Context, tenantID string, name string) error {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return err
	}
	defer release()
	return store.Delete(ctx, tenantID, name)
}

// GetDefault retrieves the default provider config for the tenant.
func (s *PoolProviderConfigStore) GetDefault(ctx context.Context, tenantID string) (*providerconfig.ProviderConfig, error) {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	return store.GetDefault(ctx, tenantID)
}

// SetDefault sets the default provider config for the tenant.
func (s *PoolProviderConfigStore) SetDefault(ctx context.Context, tenantID string, name string) error {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return err
	}
	defer release()
	return store.SetDefault(ctx, tenantID, name)
}

// GetFallbackChain retrieves the fallback chain for the tenant.
func (s *PoolProviderConfigStore) GetFallbackChain(ctx context.Context, tenantID string) ([]string, error) {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	return store.GetFallbackChain(ctx, tenantID)
}

// SetFallbackChain sets the fallback chain for the tenant.
func (s *PoolProviderConfigStore) SetFallbackChain(ctx context.Context, tenantID string, names []string) error {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return err
	}
	defer release()
	return store.SetFallbackChain(ctx, tenantID, names)
}

// Resolve resolves and decrypts a provider config for the tenant.
func (s *PoolProviderConfigStore) Resolve(ctx context.Context, tenantID string, name string) (*providerconfig.DecryptedConfig, error) {
	store, release, err := s.acquireStore(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	return store.Resolve(ctx, tenantID, name)
}
