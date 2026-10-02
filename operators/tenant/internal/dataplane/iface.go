// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package dataplane defines the Provisioner interface that the tenant
// reconciler calls to provision and deprovision per-tenant data-plane
// resources (databases, namespaced keyspaces, etc.).
//
// The concrete implementation is provided by the database-per-tenant-data-plane
// spec. Until that spec lands, the NoopProvisioner ships as the default so the
// operator can run without a real data-plane backend.
package dataplane

import (
	"context"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// Limits carries the per-tenant data-plane limits a Provision call applies.
// They come from the TenantDataPlane spec (TenantDataPlaneResources), which the
// Tenant reconciler copies from the Tenant spec. A zero value means the
// operator default for that store (gibson#545).
type Limits struct {
	// PostgresConnectionLimit is applied to the per-tenant role as
	// ALTER ROLE ... CONNECTION LIMIT N. 0 = the operator default.
	PostgresConnectionLimit int
}

// LimitsFrom reads the limits a TenantDataPlane spec declares. A nil resources
// block means every limit is the operator default.
func LimitsFrom(res *gibsonv1alpha1.TenantDataPlaneResources) Limits {
	if res == nil {
		return Limits{}
	}
	return Limits{PostgresConnectionLimit: res.PostgresConnectionLimit}
}

// Provisioner is called by the tenant reconciler to provision and deprovision
// per-tenant data-plane resources. All methods must be idempotent.
type Provisioner interface {
	// Provision allocates the per-tenant data-plane resources identified by
	// tenantID (e.g., database schemas, dedicated keyspaces). Idempotent:
	// calling Provision on an already-provisioned tenant is a no-op.
	Provision(ctx context.Context, tenantID string, limits Limits) error

	// Deprovision removes the per-tenant data-plane resources identified by
	// tenantID. Idempotent: calling Deprovision on a non-existent tenant is
	// a no-op. Callers must ensure FGA tuples and Zitadel org are cleaned up
	// before or after calling Deprovision (order is caller-defined).
	Deprovision(ctx context.Context, tenantID string) error
}
