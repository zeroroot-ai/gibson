package api

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRevokeAgentIdentity_HappyPath(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	fakeAudit := &fakeAuditWriter{}
	az := newFakeAuthorizer().allow("tenant:acme", "belongs_to", "agent_principal:some-uuid")
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
		WithAuthorizer(az).
		WithTenantAdminAuditWriter(fakeAudit)

	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:some-uuid",
	})
	if err != nil {
		t.Fatalf("RevokeAgentIdentity: %v", err)
	}
	if len(fakeidp.deleteCalls) != 1 {
		t.Errorf("expected 1 delete call, got %d", len(fakeidp.deleteCalls))
	}
	// Verify audit event emitted.
	if len(fakeAudit.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(fakeAudit.events))
	}
	if fakeAudit.events[0].Action != "agent_identity.revoked" {
		t.Errorf("audit action = %q, want %q", fakeAudit.events[0].Action, "agent_identity.revoked")
	}
}

func TestRevokeAgentIdentity_NotFound(t *testing.T) {
	fakeidp := &fakeIDPClient{
		deleteFn: func(_ context.Context, _ string) error {
			return idp.ErrNotFound
		},
	}
	az := newFakeAuthorizer().allow("tenant:acme", "belongs_to", "agent_principal:missing-id")
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:missing-id",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want NotFound", status.Code(err))
	}
}

// TestRevokeAgentIdentity_CrossTenantNotFound ensures a tenant cannot revoke a
// principal it does not own: with no belongs_to tuple for the caller's tenant,
// the call returns NotFound and never reaches the IdP delete (gibson#606).
func TestRevokeAgentIdentity_CrossTenantNotFound(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	az := newFakeAuthorizer() // no ownership tuple for tenant acme
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:other-tenants-agent",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want NotFound", status.Code(err))
	}
	if len(fakeidp.deleteCalls) != 0 {
		t.Errorf("cross-tenant revoke reached IdP delete: %d calls", len(fakeidp.deleteCalls))
	}
}

// TestRevokeAgentIdentity_FailsClosedWithoutAuthorizer ensures revoke refuses to
// delete when it cannot verify tenant ownership via FGA (gibson#606).
func TestRevokeAgentIdentity_FailsClosedWithoutAuthorizer(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp) // no authorizer
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:some-uuid",
	})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("got code %v, want Unavailable", status.Code(err))
	}
	if len(fakeidp.deleteCalls) != 0 {
		t.Errorf("fail-closed revoke reached IdP delete: %d calls", len(fakeidp.deleteCalls))
	}
}

func TestRevokeAgentIdentity_EmptyPrincipalID(t *testing.T) {
	srv := newTestDaemonServer(t).WithIdPAdminClient(&fakeIDPClient{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{PrincipalId: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("got code %v, want InvalidArgument", status.Code(err))
	}
}

func TestRevokeAgentIdentity_InvalidPrincipalIDFormat(t *testing.T) {
	srv := newTestDaemonServer(t).WithIdPAdminClient(&fakeIDPClient{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "not-a-valid-principal-id",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want NotFound (masked for security)", status.Code(err))
	}
}

func TestRevokeAgentIdentity_NoIdPConfigured(t *testing.T) {
	srv := newTestDaemonServer(t)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:some-id",
	})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("got code %v, want Unavailable", status.Code(err))
	}
}
