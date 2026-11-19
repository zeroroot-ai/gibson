// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelgate

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// GrantStore is the part of authz.Authorizer that the default grant uses.
type GrantStore interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
}

// EnsureDefaultGrant gives every member of a tenant the use of one of the
// tenant's providers, once.
//
// It writes two tuples together: tenant:<id> owner provider:<name>, and
// tenant:<id>#member can_use provider:<name>, where the provider object is
// the tenant's own (authz.ProviderObject). The owner tuple is the record
// that the default was written. When it exists, EnsureDefaultGrant writes
// nothing, so a tenant-wide grant that an administrator revoked stays
// revoked. It reports whether it wrote the default.
//
// provider is the name the gate checks: the registry name of the provider in
// the tenant's provider set. The one caller is the per-tenant slot manager
// build, so a provider gets its default before its first slot resolution,
// whether it was configured today or before this default existed.
//
// A provider that the tenant deletes keeps both tuples. They grant nothing,
// because the provider is no longer in the tenant's set, and a provider
// configured again keeps the administrator's last choice.
func EnsureDefaultGrant(ctx context.Context, az GrantStore, tenantID, provider string) (bool, error) {
	if az == nil {
		return false, errors.New("modelgate: no authorizer is configured")
	}
	object, err := authz.ProviderObject(tenantID, provider)
	if err != nil {
		return false, fmt.Errorf("modelgate: default grant: %w", err)
	}
	tenant := "tenant:" + tenantID
	owned, err := az.Check(ctx, tenant, relationOwner, object)
	if err != nil {
		return false, fmt.Errorf("modelgate: read the owner of %s: %w", object, err)
	}
	if owned {
		return false, nil
	}
	if err := az.Write(ctx, []authz.Tuple{
		{User: tenant, Relation: relationOwner, Object: object},
		{User: TenantMembers(tenantID), Relation: relationCanUse, Object: object},
	}); err != nil {
		return false, fmt.Errorf("modelgate: write the default grant on %s: %w", object, err)
	}
	return true, nil
}
