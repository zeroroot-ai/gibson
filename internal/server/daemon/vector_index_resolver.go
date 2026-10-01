// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	"github.com/zeroroot-ai/sdk/auth"
)

// secretResolver is the one secrets-service method the vector index resolver
// needs. The narrow interface lets a test supply a fake.
type secretResolver interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
}

// wireVectorStore sets the two vector fields on a pool config, or neither.
//
// Both halves must be set together: NewPool refuses a config that carries an
// address and no resolver, because the half-configured case is exactly how every
// vector-backed graph read came to answer "no vector collection provisioned" on
// a cluster whose index existed. No Redis address means no vector store to
// reach, so both stay unset and the caller logs it.
//
// Extracted from the daemon's startup path so the decision can be tested. It is
// one XOR rule that gates `recall`, QueryNodes, FindSimilarAttacks,
// FindSimilarFindings, GetRelatedFindings and GetAttackChains for every tenant,
// and inline in a 2000-line startup function nothing could reach it.
//
// Reports whether the vector store was wired.
func wireVectorStore(cfg *datapool.Config, resolver datapool.VectorIndexResolver) bool {
	if cfg == nil || cfg.RedisAddr == "" {
		return false
	}
	cfg.VectorStoreAddr = cfg.RedisAddr
	cfg.VectorIndexResolver = resolver
	return true
}

// vectorIndexResolver returns the resolver the data-plane pool uses to find a
// tenant's RediSearch index (gibson#468). It reads d.secretsService on each
// call, because the broker stack sets that field after the pool exists.
func (d *daemonImpl) vectorIndexResolver() datapool.VectorIndexResolverFunc {
	return func(ctx context.Context, tenant auth.TenantID) (string, error) {
		return resolveVectorIndex(ctx, secretReaderOf(d.secretsService), tenant)
	}
}

// secretReaderOf wraps the broker service as the narrow reader the resolver
// takes, and returns a nil INTERFACE when the service pointer is nil.
//
// This is the typed-nil trap and it has to be a function rather than three
// lines inline, because the whole point is that the obvious version is wrong:
// assigning a nil *secrets.Service into an interface variable produces an
// interface that is NOT equal to nil, so `reader != nil` is true, the resolver
// calls through it, and the daemon panics on a path that reads as a nil check.
// resolveVectorIndex returns *datapool.NotProvisionedError for a nil reader,
// which is the behaviour this preserves.
func secretReaderOf(s *secrets.Service) secretResolver {
	if s == nil {
		return nil
	}
	return s
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
