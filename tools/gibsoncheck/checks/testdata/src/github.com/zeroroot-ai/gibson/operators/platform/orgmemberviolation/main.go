// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package orgmemberviolation exercises the orgmemberwrite guard: a call to
// AddOrgMember/RemoveOrgMember from a file outside the allowlisted
// machine-user administrator-role reconciler must be flagged.
package orgmemberviolation

import (
	"context"

	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// R1 — inviting a tenant user by adding them to the org-member API. This is
// exactly the shape hosted#203 deleted: a tenant role IS the membership.
func inviteTenantUserViaOrgMember(ctx context.Context, zc zitadel.Client, orgID, userID string, roles []string) error {
	return zc.AddOrgMember(ctx, orgID, userID, roles) // want `AddOrgMember calls Zitadel's org-member API`
}

// R2 — removing a tenant user's org membership directly, instead of
// revoking their tenant role through tenantrole.Syncer.
func removeTenantUserViaOrgMember(ctx context.Context, zc zitadel.Client, orgID, userID string) error {
	return zc.RemoveOrgMember(ctx, orgID, userID) // want `RemoveOrgMember calls Zitadel's org-member API`
}

// N1 — a same-named method on an unrelated type must not be confused for
// the Zitadel client's org-member API.
type notZitadel struct{}

func (notZitadel) AddOrgMember(_ context.Context, _, _ string, _ []string) error { return nil }

func callUnrelatedAddOrgMember(ctx context.Context, n notZitadel, orgID, userID string, roles []string) error {
	return n.AddOrgMember(ctx, orgID, userID, roles)
}
