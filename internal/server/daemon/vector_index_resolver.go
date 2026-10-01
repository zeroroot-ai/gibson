// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	"github.com/zeroroot-ai/sdk/auth"
)

// secretResolver is the one secrets-service method the vector index resolver
// needs. The narrow interface lets a test supply a fake.
type secretResolver interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
}

// vectorIndexResolver returns the resolver the data-plane pool uses to find a
// tenant's RediSearch index (gibson#468). It reads d.secretsService on each
// call, because the broker stack sets that field after the pool exists.
func (d *daemonImpl) vectorIndexResolver() datapool.VectorIndexResolverFunc {
	return func(ctx context.Context, tenant auth.TenantID) (string, error) {
		// Keep the interface nil when the service is nil. A nil *Service in
		// an interface is not equal to nil.
		var reader secretResolver
		if d.secretsService != nil {
			reader = d.secretsService
		}
		return resolveVectorIndex(ctx, reader, tenant)
	}
}

// resolveVectorIndex reads VectorCredentials for the tenant from Vault and
// returns the index name.
//
// It returns *datapool.NotProvisionedError when the reader is nil or the Vault
// read fails. It returns a plain error for a malformed payload, because a
// broken payload is a fault and not an unprovisioned tenant. It returns an
// empty name with no error when the payload has no index name. The caller
// turns that case into a NotProvisionedError.
func resolveVectorIndex(ctx context.Context, reader secretResolver, tenant auth.TenantID) (string, error) {
	if reader == nil {
		return "", &datapool.NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "vector index resolver: secrets broker not yet initialized",
		}
	}
	raw, err := reader.Resolve(auth.WithTenant(ctx, tenant), pdataplane.VaultPathInfraVector)
	if err != nil {
		return "", &datapool.NotProvisionedError{
			Tenant: tenant.String(),
			Reason: fmt.Sprintf("vault read of %s failed: %v", pdataplane.VaultPathInfraVector, err),
		}
	}
	var creds pdataplane.VectorCredentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		return "", fmt.Errorf("vector index resolver: malformed VectorCredentials JSON in Vault: %w", err)
	}
	return creds.IndexName, nil
}
