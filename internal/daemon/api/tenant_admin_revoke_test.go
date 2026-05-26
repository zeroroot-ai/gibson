package api

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRevokeAgentIdentity_HappyPath(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	fakeAudit := &fakeAuditWriter{}
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
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
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:missing-id",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want NotFound", status.Code(err))
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
