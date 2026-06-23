package admin

import (
	"errors"
	"testing"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// gibson#621: SetTenantRole must project human membership to BOTH FGA (the
// existing behaviour) AND the tenant's Zitadel org. These tests cover the
// Zitadel half via the recording idp fake + a static org resolver.

func TestSetTenantRole_AddProjectsZitadelMember(t *testing.T) {
	az := &membersAuthorizer{}
	idpC := &membersIdPClient{}
	srv := newMembersTestServer(t, az, idpC)
	srv.orgResolver = staticOrgResolver{orgID: "org-123"}

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
		UserId: "alice-id",
		Role:   "admin",
	}); err != nil {
		t.Fatalf("SetTenantRole: %v", err)
	}

	if len(idpC.added) != 1 {
		t.Fatalf("expected 1 AddTenantMember call, got %d", len(idpC.added))
	}
	got := idpC.added[0]
	if got.OrgID != "org-123" || got.UserID != "alice-id" || got.Role != "admin" {
		t.Fatalf("unexpected AddTenantMember req: %+v", got)
	}
	if len(idpC.removed) != 0 {
		t.Fatalf("expected no RemoveTenantMember calls, got %d", len(idpC.removed))
	}
}

func TestSetTenantRole_RemoveLastRoleRemovesZitadelMember(t *testing.T) {
	// membersAuthorizer.Check returns false for every relation, so after the
	// role removal the user retains no tenant role → org membership is dropped.
	az := &membersAuthorizer{}
	idpC := &membersIdPClient{}
	srv := newMembersTestServer(t, az, idpC)
	srv.orgResolver = staticOrgResolver{orgID: "org-123"}

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
		UserId: "bob-id",
		Role:   "member",
		Remove: true,
	}); err != nil {
		t.Fatalf("SetTenantRole remove: %v", err)
	}

	if len(idpC.removed) != 1 {
		t.Fatalf("expected 1 RemoveTenantMember call, got %d", len(idpC.removed))
	}
	if idpC.removed[0].OrgID != "org-123" || idpC.removed[0].UserID != "bob-id" {
		t.Fatalf("unexpected RemoveTenantMember req: %+v", idpC.removed[0])
	}
}

func TestSetTenantRole_NoOrgMappingSkipsZitadel(t *testing.T) {
	az := &membersAuthorizer{}
	idpC := &membersIdPClient{}
	srv := newMembersTestServer(t, az, idpC)
	// Resolver present but returns no mapping → Zitadel half is skipped.
	srv.orgResolver = staticOrgResolver{orgID: ""}

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
		UserId: "carol-id",
		Role:   "member",
	}); err != nil {
		t.Fatalf("SetTenantRole: %v", err)
	}
	if len(idpC.added) != 0 {
		t.Fatalf("expected no AddTenantMember calls when unmapped, got %d", len(idpC.added))
	}
}

func TestSetTenantRole_ZitadelAddFailureFailsClosed(t *testing.T) {
	az := &membersAuthorizer{}
	idpC := &membersIdPClient{addErr: errors.New("zitadel down")}
	srv := newMembersTestServer(t, az, idpC)
	srv.orgResolver = staticOrgResolver{orgID: "org-123"}

	ctx := ctxWithTenant(t, "acme")
	_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
		UserId: "dave-id",
		Role:   "admin",
	})
	if err == nil {
		t.Fatal("expected SetTenantRole to fail when the Zitadel add fails (fail-closed)")
	}
}
