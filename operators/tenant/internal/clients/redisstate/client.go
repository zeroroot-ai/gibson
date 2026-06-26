// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package redisstate is the operator's client to Gibson's Redis state
// store for initializing tenant keyspaces on provisioning and deleting
// them on teardown.
package redisstate

import (
	"context"
	"time"
)

// Client is the Redis state interface for tenant lifecycle.
type Client interface {
	// InitTenantKeyspace sets the initial markers for a new tenant.
	InitTenantKeyspace(ctx context.Context, tenantID string) error

	// DeleteTenantKeyspace removes every key under tenant:{id}:* using SCAN
	// with rate limiting. Returns the number of keys deleted.
	DeleteTenantKeyspace(ctx context.Context, tenantID string) (int64, error)

	// Exists checks whether the tenant keyspace has been initialized.
	Exists(ctx context.Context, tenantID string) (bool, error)

	// Ping sends a PING command to verify the Redis connection is alive.
	Ping(ctx context.Context) error

	// PublishTenantName writes the human-readable display name for a tenant
	// into the well-known cache key (tenant:name:<id>) consumed by the
	// daemon's ListMyMemberships RPC. Idempotent.
	PublishTenantName(ctx context.Context, tenantID, name string) error

	// DeleteTenantName removes the tenant-name cache entry. Called on
	// Tenant CR deletion to keep the cache in sync.
	DeleteTenantName(ctx context.Context, tenantID string) error
}

// Config holds connection details.
type Config struct {
	Addr            string
	Password        string
	DB              int
	DeleteBatchSize int
	DeleteSleep     time.Duration
}
