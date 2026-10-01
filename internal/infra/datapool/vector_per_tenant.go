// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool/vectordb"
	"github.com/zeroroot-ai/sdk/auth"
)

// VectorIndexResolver resolves the RediSearch index name for one tenant.
//
// The tenant-operator creates the index and records its name in Vault at
// tenant/<id>/infra/vector (pkg/platform/dataplane.VectorCredentials). Vault is
// the one source of truth for the name: the datapool layer must not derive it,
// because a second derivation is a second thing to keep in step with the
// operator (gibson#106 keeps Vault reads out of this layer, so the daemon
// supplies the closure).
type VectorIndexResolver interface {
	// VectorIndex returns the full index name, for example
	// "vector_idx:tenant_acme". An empty name means the tenant has no vector
	// collection, which the caller reports as *NotProvisionedError.
	VectorIndex(ctx context.Context, tenant auth.TenantID) (string, error)
}

// VectorIndexResolverFunc adapts a function to VectorIndexResolver.
type VectorIndexResolverFunc func(ctx context.Context, tenant auth.TenantID) (string, error)

// VectorIndex implements VectorIndexResolver.
func (f VectorIndexResolverFunc) VectorIndex(ctx context.Context, tenant auth.TenantID) (string, error) {
	return f(ctx, tenant)
}

// validateVectorConfig refuses a half-configured vector store.
//
// An address with no resolver cannot name an index, and a resolver with no
// address has nothing to dial. Either way every vector-backed read refuses,
// and it refuses with "no vector collection provisioned", which reads as a
// provisioning gap on the tenant rather than a configuration gap on the
// daemon. That mistranslation is gibson#468, so the config fails loudly
// instead.
func validateVectorConfig(cfg Config) error {
	hasAddr := cfg.VectorStoreAddr != ""
	hasResolver := cfg.VectorIndexResolver != nil
	if hasAddr == hasResolver {
		return nil
	}
	return fmt.Errorf(
		"VectorStoreAddr and VectorIndexResolver must be set together (addr set: %t, resolver set: %t)",
		hasAddr, hasResolver)
}

// vectorPerTenant wraps the vectordb.Driver to provide per-tenant index
// access. The index name comes from the resolver, never from this package.
type vectorPerTenant struct {
	driver   vectordb.Driver
	resolver VectorIndexResolver
}

func newVectorPerTenant(driver vectordb.Driver, resolver VectorIndexResolver) *vectorPerTenant {
	return &vectorPerTenant{driver: driver, resolver: resolver}
}

// ForTenant returns a vectordb.Client bound to the tenant's dedicated
// RediSearch index.
//
// Returns *NotProvisionedError when the tenant has no index recorded, and when
// the recorded index does not exist in the store.
func (v *vectorPerTenant) ForTenant(ctx context.Context, tenant auth.TenantID) (vectordb.Client, error) {
	index, err := v.resolver.VectorIndex(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("datapool: vector: resolve index for tenant %s: %w", tenant, err)
	}
	if index == "" {
		return nil, &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "no vector index recorded at infra/vector",
		}
	}

	client, err := v.driver.For(ctx, index)
	if err != nil {
		if isVectorCollectionNotExist(err, index) {
			return nil, &NotProvisionedError{
				Tenant: tenant.String(),
				Reason: fmt.Sprintf("vector index %q does not exist", index),
			}
		}
		return nil, fmt.Errorf("datapool: vector: failed to get client for tenant %s (index %s): %w", tenant, index, err)
	}
	return client, nil
}

// Close shuts down the underlying vector Driver.
func (v *vectorPerTenant) Close() error {
	return v.driver.Close()
}

// isVectorCollectionNotExist returns true if the error indicates the vector
// index does not exist. The Redis VSS adapter populates errors with the index
// name in a detectable way.
func isVectorCollectionNotExist(err error, index string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, fmt.Sprintf("index %q", index))
}
