// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// tenant_admin_removal_test.go covers Removal (ADR-0093 §11, hosted#205):
//
//   - RemoveMember and LeaveTenant both refuse a target/caller who holds the
//     tenant's owner relation.
//   - A successful call revokes the target's IdP sessions, stamps their
//     active_session FGA tuples (the same instant-revocation gate
//     RevokeUserSessions uses), revokes their tenant role, and deletes their
//     Zitadel account.
//   - Every collaborator-error branch fails Internal, and a call that names
//     another tenant is rejected before anything is touched.
package admin

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// removalAuthorizer extends ownershipAuthorizer with the ConditionalWriter
// methods removeTenantUser's session-revocation stamp needs, without
// changing the shared ownershipAuthorizer fake other tests build on.
type removalAuthorizer struct {
	*ownershipAuthorizer

	stampErr     error
	stampedCalls int
}

func newRemovalAuthorizer() *removalAuthorizer {
	return &removalAuthorizer{ownershipAuthorizer: newOwnershipAuthorizer()}
}

func (a *removalAuthorizer) WriteConditional(_ context.Context, _ authz.ConditionalTuple) error {
	if a.stampErr != nil {
		return a.stampErr
	}
	a.stampedCalls++
	return nil
}

func (a *removalAuthorizer) UpdateConditionalTuple(_ context.Context, _ authz.ConditionalTuple) error {
	if a.stampErr != nil {
		return a.stampErr
	}
	a.stampedCalls++
	return nil
}

// newRemovalTestServer wires a TenantAdminServer whose authorizer is a
// removalAuthorizer (so the ConditionalWriter stamp path is exercised) and
// whose roles Syncer is backed by fakeGrants, mirroring
// newOwnershipTestServerWithGrants.
func newRemovalTestServer(t *testing.T, az *removalAuthorizer, idpC *membersIdPClient) (*TenantAdminServer, *fakeGrants) {
	t.Helper()
	srv := newMembersTestServer(t, &membersAuthorizer{}, idpC)
	srv.authorizer = az
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	grants := newFakeGrants()
	srv.roles = tenantrole.NewSyncer(grants, tuples, nil)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	return srv, grants
}

// ---------------------------------------------------------------------------
// RemoveMember
// ---------------------------------------------------------------------------

func TestRemoveMember_RefusesOwner(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	idpC := &membersIdPClient{}
	srv, grants := newRemovalTestServer(t, az, idpC)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "owner-x"})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("RemoveMember code = %v (err=%v), want PermissionDenied", got, err)
	}
	if len(idpC.revokedSessionsFor) != 0 {
		t.Errorf("must not revoke sessions for a refused removal; got %v", idpC.revokedSessionsFor)
	}
	if len(idpC.deletedHumanUsers) != 0 {
		t.Errorf("must not delete the account for a refused removal; got %+v", idpC.deletedHumanUsers)
	}
	if len(grants.grants) != 0 {
		t.Errorf("must not touch any Zitadel grant for a refused removal")
	}
}

func TestRemoveMember_Succeeds(t *testing.T) {
	az := newRemovalAuthorizer()
	ft := newOwnershipTenant(ownCaller) // caller is Owner, so has "admin" too
	ft.member["user:carol-id"] = true
	az.tenants[ownTenantID] = ft
	idpC := &membersIdPClient{}
	srv, grants := newRemovalTestServer(t, az, idpC)
	grantID, err := grants.Create(context.Background(), "org-1", "carol-id", tenantrole.Viewer)
	if err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	ctx := ctxWithTenant(t, ownTenant)
	if _, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"}); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	if len(idpC.revokedSessionsFor) != 1 || idpC.revokedSessionsFor[0] != "carol-id" {
		t.Errorf("expected sessions revoked for carol-id, got %v", idpC.revokedSessionsFor)
	}
	if az.stampedCalls != 2 {
		t.Errorf("expected both the user-scoped and per-tenant active_session tuples stamped, got %d calls", az.stampedCalls)
	}
	if len(idpC.deletedHumanUsers) != 1 {
		t.Fatalf("expected exactly one DeleteHumanUser call, got %d", len(idpC.deletedHumanUsers))
	}
	if got := idpC.deletedHumanUsers[0]; got.UserID != "carol-id" || got.OrgID != "org-1" {
		t.Errorf("DeleteHumanUser request = %+v, want {OrgID: org-1, UserID: carol-id}", got)
	}
	if _, stillPresent := grants.grants[grantID]; stillPresent {
		t.Errorf("expected grant %s to be deleted by Revoke, got %+v", grantID, grants.grants)
	}
}

func TestRemoveMember_NoUserID(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	srv, _ := newRemovalTestServer(t, az, &membersIdPClient{})

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{})
	if got := grpcCodeOf(err); got != codes.InvalidArgument {
		t.Fatalf("RemoveMember code = %v (err=%v), want InvalidArgument", got, err)
	}
}

func TestRemoveMember_ForeignTenantRejected(t *testing.T) {
	az := &tenantScopeAuthorizer{checkResult: true}
	srv := newMembersTestServer(t, &membersAuthorizer{}, &membersIdPClient{})
	srv.authorizer = az

	ctx := ctxWithTenant(t, scopeCallerTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{
		TenantId: scopeForeignTenant,
		UserId:   "victim-id",
	})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("RemoveMember code = %v (err=%v), want PermissionDenied", got, err)
	}
	if len(az.wrote) != 0 || len(az.deleted) != 0 {
		t.Errorf("rejected call mutated FGA: wrote=%+v deleted=%+v", az.wrote, az.deleted)
	}
}

func TestRemoveMember_UnavailableWithoutAuthorizer(t *testing.T) {
	srv := newMembersTestServer(t, &membersAuthorizer{}, &membersIdPClient{})
	srv.authorizer = nil

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Unavailable {
		t.Fatalf("RemoveMember code = %v (err=%v), want Unavailable", got, err)
	}
}

func TestRemoveMember_UnavailableWithoutRoles(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	srv := newMembersTestServer(t, &membersAuthorizer{}, &membersIdPClient{})
	srv.authorizer = az
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	// srv.roles left nil.

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Unavailable {
		t.Fatalf("RemoveMember code = %v (err=%v), want Unavailable", got, err)
	}
}

func TestRemoveMember_UnavailableWithoutIdPClient(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	srv, _ := newRemovalTestServer(t, az, nil)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Unavailable {
		t.Fatalf("RemoveMember code = %v (err=%v), want Unavailable", got, err)
	}
}

func TestRemoveMember_OwnerCheckErrorIsInternal(t *testing.T) {
	az := newRemovalAuthorizer()
	az.checkErr = map[string]error{"owner": errors.New("fga boom")}
	srv, _ := newRemovalTestServer(t, az, &membersIdPClient{})

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("RemoveMember code = %v (err=%v), want Internal", got, err)
	}
}

func TestRemoveMember_TenantOfErrorPropagates(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	srv, _ := newRemovalTestServer(t, az, &membersIdPClient{})
	srv.orgResolver = staticOrgResolver{err: errors.New("resolver boom")}

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("RemoveMember code = %v (err=%v), want Internal (tenantOf's error passed through)", got, err)
	}
}

func TestRemoveMember_RevokeSessionsErrorIsInternal(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	idpC := &membersIdPClient{revokeSessionsErr: errors.New("idp boom")}
	srv, grants := newRemovalTestServer(t, az, idpC)
	if _, err := grants.Create(context.Background(), "org-1", "carol-id", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("RemoveMember code = %v (err=%v), want Internal", got, err)
	}
	if len(idpC.deletedHumanUsers) != 0 {
		t.Error("must not delete the account when session revocation failed")
	}
	if len(grants.grants) != 1 {
		t.Error("must not revoke the tenant role when session revocation failed")
	}
}

func TestRemoveMember_RoleRevokeErrorIsInternal(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	idpC := &membersIdPClient{}
	srv, grants := newRemovalTestServer(t, az, idpC)
	grants.deleteErr = errors.New("zitadel boom")
	if _, err := grants.Create(context.Background(), "org-1", "carol-id", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("RemoveMember code = %v (err=%v), want Internal", got, err)
	}
	if len(idpC.deletedHumanUsers) != 0 {
		t.Error("must not delete the account when the role revoke failed")
	}
	if len(idpC.revokedSessionsFor) != 1 {
		t.Error("sessions must already be revoked even though the role revoke failed later")
	}
}

func TestRemoveMember_DeleteHumanUserErrorIsInternal(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	idpC := &membersIdPClient{deleteHumanUserErr: errors.New("zitadel boom")}
	srv, grants := newRemovalTestServer(t, az, idpC)
	if _, err := grants.Create(context.Background(), "org-1", "carol-id", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("RemoveMember code = %v (err=%v), want Internal", got, err)
	}
	if len(grants.grants) != 0 {
		t.Error("the role must already be revoked even though the account delete failed")
	}
}

// ---------------------------------------------------------------------------
// LeaveTenant
// ---------------------------------------------------------------------------

func TestLeaveTenant_RefusesOwner(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller) // caller ("user-1") is Owner
	idpC := &membersIdPClient{}
	srv, _ := newRemovalTestServer(t, az, idpC)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.LeaveTenant(ctx, &tenantv1.LeaveTenantRequest{})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("LeaveTenant code = %v (err=%v), want PermissionDenied", got, err)
	}
	if len(idpC.revokedSessionsFor) != 0 {
		t.Errorf("must not revoke sessions for a refused leave; got %v", idpC.revokedSessionsFor)
	}
}

func TestLeaveTenant_Succeeds(t *testing.T) {
	az := newRemovalAuthorizer()
	ft := newOwnershipTenant("user:owner-x")
	ft.member[ownCaller] = true // the caller is a plain member, not the Owner
	az.tenants[ownTenantID] = ft
	idpC := &membersIdPClient{}
	srv, grants := newRemovalTestServer(t, az, idpC)
	if _, err := grants.Create(context.Background(), "org-1", "user-1", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	ctx := ctxWithTenant(t, ownTenant)
	if _, err := srv.LeaveTenant(ctx, &tenantv1.LeaveTenantRequest{}); err != nil {
		t.Fatalf("LeaveTenant: %v", err)
	}

	if len(idpC.revokedSessionsFor) != 1 || idpC.revokedSessionsFor[0] != "user-1" {
		t.Errorf("expected sessions revoked for the caller (user-1), got %v", idpC.revokedSessionsFor)
	}
	if len(idpC.deletedHumanUsers) != 1 || idpC.deletedHumanUsers[0].UserID != "user-1" {
		t.Errorf("expected the caller's own account deleted, got %+v", idpC.deletedHumanUsers)
	}
	if len(grants.grants) != 0 {
		t.Error("expected the caller's own tenant role grant to be revoked")
	}
}

func TestLeaveTenant_NoIdentityInContext(t *testing.T) {
	az := newRemovalAuthorizer()
	srv, _ := newRemovalTestServer(t, az, &membersIdPClient{})

	_, err := srv.LeaveTenant(context.Background(), &tenantv1.LeaveTenantRequest{})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("LeaveTenant code = %v (err=%v), want PermissionDenied", got, err)
	}
}

func TestLeaveTenant_ForeignTenantRejected(t *testing.T) {
	az := &tenantScopeAuthorizer{checkResult: true}
	srv := newMembersTestServer(t, &membersAuthorizer{}, &membersIdPClient{})
	srv.authorizer = az

	ctx := ctxWithTenant(t, scopeCallerTenant)
	_, err := srv.LeaveTenant(ctx, &tenantv1.LeaveTenantRequest{TenantId: scopeForeignTenant})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("LeaveTenant code = %v (err=%v), want PermissionDenied", got, err)
	}
	if len(az.wrote) != 0 || len(az.deleted) != 0 {
		t.Errorf("rejected call mutated FGA: wrote=%+v deleted=%+v", az.wrote, az.deleted)
	}
}

func TestLeaveTenant_UnavailableWithoutRoles(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv := newMembersTestServer(t, &membersAuthorizer{}, &membersIdPClient{})
	srv.authorizer = az
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	// srv.roles left nil.

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.LeaveTenant(ctx, &tenantv1.LeaveTenantRequest{})
	if got := grpcCodeOf(err); got != codes.Unavailable {
		t.Fatalf("LeaveTenant code = %v (err=%v), want Unavailable", got, err)
	}
}

// TestRemoveMember_StampFailureIsNonFatal proves the FGA active_session stamp
// is best-effort: the IdP session revocation already happened and must not
// be rolled back by a downstream FGA hiccup, mirroring RevokeUserSessions'
// own contract.
func TestRemoveMember_StampFailureIsNonFatal(t *testing.T) {
	az := newRemovalAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	az.stampErr = errors.New("fga conditional write boom")
	idpC := &membersIdPClient{}
	srv, grants := newRemovalTestServer(t, az, idpC)
	if _, err := grants.Create(context.Background(), "org-1", "carol-id", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	ctx := ctxWithTenant(t, ownTenant)
	if _, err := srv.RemoveMember(ctx, &tenantv1.RemoveMemberRequest{UserId: "carol-id"}); err != nil {
		t.Fatalf("RemoveMember: %v, want the stamp failure to be swallowed", err)
	}
	if len(idpC.deletedHumanUsers) != 1 {
		t.Error("removal must still complete when the FGA stamp fails")
	}
}

// idpAdminClientCompileCheck pins that *membersIdPClient still satisfies
// idp.AdminClient after the removal-recording additions above.
var _ idp.AdminClient = (*membersIdPClient)(nil)
