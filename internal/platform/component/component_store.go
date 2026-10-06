// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package component provides component management for Gibson.
// This file defines the ComponentStore interface and shared types used by
// storage implementations (Redis-backed).

package component

import (
	"context"
)

// ComponentStore provides storage operations for installed components.
// Component metadata is stored persistently (no TTL) in a backing store.
//
// Keys follow the pattern:
//
//	{namespace}:components:{kind}:{name}
//
// Running instances are tracked separately:
//
//	{namespace}:components:{kind}:{name}:instances:{instance_id}
type ComponentStore interface {
	// Create stores a new component's metadata (no TTL).
	// Returns ErrComponentExists if (kind, name) already exists.
	Create(ctx context.Context, comp *Component) error

	// GetByName retrieves component metadata by kind and name.
	// Returns nil, nil if not found.
	GetByName(ctx context.Context, kind ComponentKind, name string) (*Component, error)

	// List returns all components of a specific kind.
	List(ctx context.Context, kind ComponentKind) ([]*Component, error)

	// ListAll returns all components across all kinds.
	ListAll(ctx context.Context) (map[ComponentKind][]*Component, error)

	// Update updates component metadata (version, paths, manifest).
	Update(ctx context.Context, comp *Component) error

	// Delete removes component metadata and all running instances.
	Delete(ctx context.Context, kind ComponentKind, name string) error

	// ListInstances returns all running instances for a component.
	ListInstances(ctx context.Context, kind ComponentKind, name string) ([]ComponentInfo, error)
}
