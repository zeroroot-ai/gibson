package redis

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/types"
)

// TargetDAO defines the interface for target data access operations.
type TargetDAO interface {
	// Create inserts a new target
	Create(ctx context.Context, target *types.Target) error

	// Get retrieves a target by ID
	Get(ctx context.Context, id types.ID) (*types.Target, error)

	// GetByName retrieves a target by name
	GetByName(ctx context.Context, name string) (*types.Target, error)

	// List retrieves targets with optional filtering
	List(ctx context.Context, filter *types.TargetFilter) ([]*types.Target, error)

	// Update updates an existing target
	Update(ctx context.Context, target *types.Target) error

	// Delete deletes a target by ID
	Delete(ctx context.Context, id types.ID) error

	// DeleteByName deletes a target by name
	DeleteByName(ctx context.Context, name string) error

	// Exists checks if a target with the given name exists
	Exists(ctx context.Context, name string) (bool, error)
}
