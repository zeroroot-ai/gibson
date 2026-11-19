// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelgate

import (
	"context"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// relationCanUse is the FGA relation the gate checks on a model and on a
// provider.
const relationCanUse = "can_use"

// relationOwner links a tenant to a provider it configured. It is also the
// record that the tenant-wide default grant was written once.
const relationOwner = "owner"

// TenantMembers is the FGA userset of every member of a tenant.
func TenantMembers(tenantID string) string { return "tenant:" + tenantID + "#member" }

// Subject returns the FGA subject the gate decides for, or "" when the
// request names no user, no component and no tenant. The order is the one in
// the package doc: the acting user, the mission initiator, the calling
// identity, then the tenant's members as a set.
func Subject(ctx context.Context) string {
	if u, ok := auth.ActingUserFromContext(ctx); ok {
		return "user:" + u
	}
	if u, ok := auth.InitiatorUserFromContext(ctx); ok {
		return "user:" + u
	}
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		// The FGA user of the caller: a typed principal unchanged, otherwise
		// "user:<subject>" with a SPIFFE scheme stripped. Every tuple of a
		// SPIFFE caller has that form, so "user:spiffe://..." never matched
		// one (gibson#13 found the same split for records).
		return principal.FGAUser(id)
	}
	if tenantID := auth.TenantStringFromContext(ctx); tenantID != "" {
		return TenantMembers(tenantID)
	}
	return ""
}
