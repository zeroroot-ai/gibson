package postgres

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/types"
)

// CredentialDAO defines the interface for credential data access operations
// against the per-tenant Postgres credential store.
type CredentialDAO interface {
	// Create inserts a new credential
	Create(ctx context.Context, cred *types.Credential) error

	// Get retrieves a credential by ID
	Get(ctx context.Context, id types.ID) (*types.Credential, error)

	// GetByName retrieves a credential by name
	GetByName(ctx context.Context, name string) (*types.Credential, error)

	// List retrieves credentials with optional filtering
	List(ctx context.Context, filter *types.CredentialFilter) ([]*types.Credential, error)

	// Update updates an existing credential
	Update(ctx context.Context, cred *types.Credential) error

	// Delete deletes a credential by ID
	Delete(ctx context.Context, id types.ID) error

	// DeleteByName deletes a credential by name
	DeleteByName(ctx context.Context, name string) error

	// Exists checks if a credential with the given name exists
	Exists(ctx context.Context, name string) (bool, error)
}
