package daemon

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
)

// DaemonCredentialStore implements harness.CredentialStore using the
// daemon's Postgres-backed CredentialDAO with envelope encryption.
//
// Phase C: credentials are stored in Postgres using AES Key Wrap DEK +
// AES-256-GCM per-record envelope encryption. The keyProvider is retained for
// Health() and Close() — the actual decryption is performed inside
// database.PostgresCredentialDAO, which holds the KEK.
type DaemonCredentialStore struct {
	dao         database.CredentialDAO
	keyProvider crypto.KeyProvider
}

// NewDaemonCredentialStore creates a new credential store for the daemon.
// dao must be a database.CredentialDAO backed by the per-tenant Postgres
// store (database.PostgresCredentialDAO or equivalent). The keyProvider is
// used for Health() and Close(); decryption is handled by the DAO itself.
func NewDaemonCredentialStore(dao database.CredentialDAO, keyProvider crypto.KeyProvider) (*DaemonCredentialStore, error) {
	if dao == nil {
		return nil, fmt.Errorf("credential DAO cannot be nil")
	}
	if keyProvider == nil {
		return nil, fmt.Errorf("key provider cannot be nil")
	}

	return &DaemonCredentialStore{
		dao:         dao,
		keyProvider: keyProvider,
	}, nil
}

// GetCredential retrieves a credential by name.
// The PostgresCredentialDAO performs envelope decryption internally; the
// plaintext secret is returned in cred.EncryptedValue (legacy field reuse).
// The returned string is the decrypted plaintext secret.
//
// SECURITY: never log or persist the returned string value.
func (s *DaemonCredentialStore) GetCredential(ctx context.Context, name string) (*types.Credential, string, error) {
	cred, err := s.dao.GetByName(ctx, name)
	if err != nil {
		return nil, "", fmt.Errorf("credential %q not found: %w", name, err)
	}
	// PostgresCredentialDAO.GetByName decrypts via envelope and stores the
	// plaintext secret bytes in cred.EncryptedValue for backward compat.
	secret := string(cred.EncryptedValue)
	return cred, secret, nil
}

// Health returns the health status of the key provider.
func (s *DaemonCredentialStore) Health(ctx context.Context) types.HealthStatus {
	return s.keyProvider.Health(ctx)
}

// Close releases resources.
func (s *DaemonCredentialStore) Close() error {
	return s.keyProvider.Close()
}

// Ensure DaemonCredentialStore implements harness.CredentialStore
var _ harness.CredentialStore = (*DaemonCredentialStore)(nil)
