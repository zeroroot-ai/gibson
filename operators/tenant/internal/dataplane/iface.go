/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
