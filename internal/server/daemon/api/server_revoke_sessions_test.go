package api

import (
	"context"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

func revokeServer(az authzIface, idpC *fakeIDPClient) *DaemonServer {
	return &DaemonServer{logger: slog.Default(), authorizer: az, idpAdminClient: idpC}
}

func TestRevokeUserSessions_Self(t *testing.T) {
	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{SessionsTerminated: 2, GrantsRevoked: 2}}
	// No authorizer needed for self; ensure it is not consulted by passing nil.
	srv := revokeServer(nil, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "alice")

	resp, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "alice"})
	if err != nil {
		t.Fatalf("self revoke: %v", err)
	}
	if resp.GetSessionsTerminated() != 2 || resp.GetGrantsRevoked() != 2 {
		t.Fatalf("unexpected counts: %+v", resp)
	}
	if len(idpC.revokedUsers) != 1 || idpC.revokedUsers[0] != "alice" {
		t.Fatalf("expected idp revoke for alice, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_TenantAdminOverMember(t *testing.T) {
	az := newFakeAuthorizer().
		allow("user:admin1", "admin", "tenant:acme").
		allow("user:bob", "member", "tenant:acme")
	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{SessionsTerminated: 1, GrantsRevoked: 1}}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	if _, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "bob"}); err != nil {
		t.Fatalf("tenant admin revoke: %v", err)
	}
	if len(idpC.revokedUsers) != 1 {
		t.Fatalf("expected idp revoke, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_TeamAdminOverTeamMember(t *testing.T) {
	az := newFakeAuthorizer().
		withObjects("user:lead", "admin", "team", "team:red").
		allow("user:carol", "member", "team:red")
	idpC := &fakeIDPClient{revokeResult: idp.RevokeUserSessionsResult{SessionsTerminated: 1, GrantsRevoked: 1}}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "lead")

	if _, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "carol"}); err != nil {
		t.Fatalf("team admin revoke: %v", err)
	}
	if len(idpC.revokedUsers) != 1 {
		t.Fatalf("expected idp revoke, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_UnrelatedPeerDenied(t *testing.T) {
	// caller is neither tenant admin nor a team admin over the target.
	az := newFakeAuthorizer()
	idpC := &fakeIDPClient{}
	srv := revokeServer(az, idpC)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "mallory")

	_, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{TargetUserId: "victim"})
	if status_grpc.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
	if len(idpC.revokedUsers) != 0 {
		t.Fatalf("idp must NOT be called when denied, got %v", idpC.revokedUsers)
	}
}

func TestRevokeUserSessions_MissingTarget(t *testing.T) {
	srv := revokeServer(newFakeAuthorizer(), &fakeIDPClient{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "alice")
	_, err := srv.RevokeUserSessions(ctx, &tenantv1.RevokeUserSessionsRequest{})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}
