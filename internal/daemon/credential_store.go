package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/auth"
)

// DaemonCredentialStore implements harness.CredentialStore using the
// per-tenant data-plane Pool. Each GetCredential call acquires a Conn
// for the calling tenant (resolved from context), calls conn.Credentials().Get,
// and releases the Conn before returning.
//
// Phase D: this replaces the Phase C bridge (PostgresCredentialDAO wrapping a
// shared credentialPGPool pointing at the dashboard Postgres). Credentials are
// now stored in each tenant's own Postgres database, wrapped under the per-tenant
// KEK via envelope encryption (see internal/database.CredentialOps).
type DaemonCredentialStore struct {
	pool        datapool.Pool
	keyProvider crypto.KeyProvider
}

// NewDaemonCredentialStore creates a new pool-backed credential store.
// pool must not be nil; it is used to acquire a per-tenant Conn per RPC call.
// keyProvider is retained for Health() and Close().
func NewDaemonCredentialStore(pool datapool.Pool, keyProvider crypto.KeyProvider) (*DaemonCredentialStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("credential store: pool must not be nil")
	}
	if keyProvider == nil {
		return nil, fmt.Errorf("credential store: keyProvider must not be nil")
	}
	return &DaemonCredentialStore{
		pool:        pool,
		keyProvider: keyProvider,
	}, nil
}

// GetCredential retrieves a credential by name for the tenant in context.
// It acquires a per-tenant Conn, calls conn.Credentials().Get(ctx, name),
// and releases the Conn. The decrypted plaintext secret is returned as the
// second return value.
//
// SECURITY: never log or persist the returned secret string.
func (s *DaemonCredentialStore) GetCredential(ctx context.Context, name string) (*types.Credential, string, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, "", fmt.Errorf("credential store: no tenant in context")
	}

	conn, err := s.pool.For(ctx, tenant)
	if err != nil {
		var npErr *datapool.NotProvisionedError
		if errors.As(err, &npErr) {
			return nil, "", fmt.Errorf("credential store: tenant %s not provisioned", tenant)
		}
		return nil, "", fmt.Errorf("credential store: acquire conn: %w", err)
	}
	defer conn.Release()

	secretBytes, err := conn.Credentials().Get(ctx, name)
	if err != nil {
		if errors.Is(err, database.ErrCredentialNotFound) {
			return nil, "", fmt.Errorf("credential %q not found", name)
		}
		return nil, "", fmt.Errorf("credential store: get %q: %w", name, err)
	}

	// Build a minimal Credential for the harness API.
	// The harness only uses Name and the plaintext secret; other fields
	// are not required by the CredentialStore interface contract.
	cred := &types.Credential{
		ID:   types.NewID(),
		Name: name,
	}
	return cred, string(secretBytes), nil
}

// Health returns the health status of the key provider.
func (s *DaemonCredentialStore) Health(ctx context.Context) types.HealthStatus {
	return s.keyProvider.Health(ctx)
}

// Close releases resources.
func (s *DaemonCredentialStore) Close() error {
	return s.keyProvider.Close()
}

// Ensure DaemonCredentialStore implements harness.CredentialStore.
var _ harness.CredentialStore = (*DaemonCredentialStore)(nil)
