// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package dataplane defines the Provisioner interface that the tenant
// reconciler calls to provision and deprovision per-tenant data-plane
// resources (databases, namespaced keyspaces, etc.).
//
// The concrete implementation is provided by the database-per-tenant-data-plane
// spec. Until that spec lands, the NoopProvisioner ships as the default so the
// operator can run without a real data-plane backend.
package dataplane

import "context"

// Provisioner is called by the tenant reconciler to provision and deprovision
// per-tenant data-plane resources. All methods must be idempotent.
type Provisioner interface {
	// Provision allocates the per-tenant data-plane resources identified by
	// tenantID (e.g., database schemas, dedicated keyspaces). Idempotent:
	// calling Provision on an already-provisioned tenant is a no-op.
	Provision(ctx context.Context, tenantID string) error

	// Deprovision removes the per-tenant data-plane resources identified by
	// tenantID. Idempotent: calling Deprovision on a non-existent tenant is
	// a no-op. Callers must ensure FGA tuples and Zitadel org are cleaned up
	// before or after calling Deprovision (order is caller-defined).
	Deprovision(ctx context.Context, tenantID string) error
}
