// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
)

func TestRevokeAgentIdentity_HappyPath(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	fakeAudit := &fakeAuditWriter{}
	az := newFakeAuthorizer().allow("tenant:acme", "belongs_to", "agent_principal:some-uuid")
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
		WithAuthorizer(az).
		WithPrincipalRevoker(&fakePrincipalRevoker{}).
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
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az).WithPrincipalRevoker(&fakePrincipalRevoker{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:missing-id",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want NotFound", status.Code(err))
	}
}

// TestRevokeAgentIdentity_OrphanInTenantScope: an identity whose FGA tuples
// never landed (or were cleaned) still has its IdP account. When the IdP lists
// that account in the caller tenant's scope, revoke deletes it instead of
// answering NotFound and leaving the name blocked forever.
func TestRevokeAgentIdentity_OrphanInTenantScope(t *testing.T) {
	var listedScope string
	fakeidp := &fakeIDPClient{
		listFn: func(_ context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			listedScope = req.TenantScopeID
			return &idp.ListServiceAccountsResponse{ServiceAccounts: []idp.ServiceAccount{
				{AccountID: "orphan-id", Name: "agent-acme-zerocool-claude", Role: idp.RoleAgent},
			}}, nil
		},
	}
	az := newFakeAuthorizer() // no belongs_to tuple at all
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az).WithPrincipalRevoker(&fakePrincipalRevoker{})
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.RevokeAgentIdentity(ctx, &tenantpb.RevokeAgentIdentityRequest{
		PrincipalId: "agent_principal:orphan-id",
	})
	if err != nil {
		t.Fatalf("RevokeAgentIdentity: %v", err)
	}
	if listedScope != "acme" {
		t.Errorf("IdP list scoped to %q, want the caller tenant acme", listedScope)
	}
	if len(fakeidp.deleteCalls) != 1 || fakeidp.deleteCalls[0] != "orphan-id" {
		t.Errorf("DeleteServiceAccount calls = %v, want [orphan-id]", fakeidp.deleteCalls)
	}
}

// TestRevokeAgentIdentity_CrossTenantNotFound ensures a tenant cannot revoke a
// principal it does not own: with no belongs_to tuple for the caller's tenant,
// the call returns NotFound and never reaches the IdP delete (gibson#606).
func TestRevokeAgentIdentity_CrossTenantNotFound(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	az := newFakeAuthorizer() // no ownership tuple for tenant acme
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az).WithPrincipalRevoker(&fakePrincipalRevoker{})
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

// TestServiceAccountInTenantScope covers the kind→role mapping, paging, the
// IdP error path and the unknown-type guard of the orphan lookup.
func TestServiceAccountInTenantScope(t *testing.T) {
	t.Run("maps each kind to its role and finds the account on a later page", func(t *testing.T) {
		for fgaType, wantRole := range map[string]idp.Role{
			"agent_principal":  idp.RoleAgent,
			"tool_principal":   idp.RoleTool,
			"plugin_principal": idp.RolePlugin,
		} {
			var roles []idp.Role
			fakeidp := &fakeIDPClient{
				listFn: func(_ context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
					roles = append(roles, req.RoleFilter)
					if req.PageToken == "" {
						return &idp.ListServiceAccountsResponse{
							ServiceAccounts: []idp.ServiceAccount{{AccountID: "other"}},
							NextPageToken:   "p2",
						}, nil
					}
					return &idp.ListServiceAccountsResponse{ServiceAccounts: []idp.ServiceAccount{{AccountID: "wanted"}}}, nil
				},
			}
			srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
			found, err := srv.serviceAccountInTenantScope(context.Background(), "acme", fgaType, "wanted")
			if err != nil || !found {
				t.Fatalf("%s: found=%v err=%v, want found on page 2", fgaType, found, err)
			}
			if len(roles) != 2 || roles[0] != wantRole || roles[1] != wantRole {
				t.Errorf("%s: roles asked = %v, want [%s %s]", fgaType, roles, wantRole, wantRole)
			}
		}
	})
	t.Run("absent account is a miss", func(t *testing.T) {
		srv := newTestDaemonServer(t).WithIdPAdminClient(&fakeIDPClient{})
		found, err := srv.serviceAccountInTenantScope(context.Background(), "acme", "agent_principal", "nope")
		if err != nil || found {
			t.Fatalf("found=%v err=%v, want miss without error", found, err)
		}
	})
	t.Run("IdP list error propagates", func(t *testing.T) {
		fakeidp := &fakeIDPClient{listFn: func(context.Context, idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			return nil, errors.New("idp down")
		}}
		srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
		if _, err := srv.serviceAccountInTenantScope(context.Background(), "acme", "agent_principal", "x"); err == nil {
			t.Fatal("expected the IdP error")
		}
	})
	t.Run("unknown principal type is an error", func(t *testing.T) {
		srv := newTestDaemonServer(t).WithIdPAdminClient(&fakeIDPClient{})
		if _, err := srv.serviceAccountInTenantScope(context.Background(), "acme", "user", "x"); err == nil {
			t.Fatal("expected an error for an unknown principal type")
		}
	})
}

// fakePrincipalRevoker records the principals whose Capability Grant rows it revoked.
type fakePrincipalRevoker struct {
	calls []string
	err   error
}

func (f *fakePrincipalRevoker) RevokePrincipal(_ context.Context, tenantID, principalRef string) error {
	f.calls = append(f.calls, tenantID+"|"+principalRef)
	return f.err
}

// A revoke sets the Capability Grant rows of the identity to revoked, so its key
// descriptor is withheld, and it deletes each grant of the identity to a published
// mission definition. Without both, the identity keeps its key and its grants.
func TestRevokeAgentIdentity_RevokesTheCapabilityGrantsAndTheInboundGrants(t *testing.T) {
	const principal = "agent_principal:some-uuid"
	az := &recordingAuthorizer{fakeAuthorizer: newFakeAuthorizer().allow("tenant:acme", "belongs_to", principal)}
	az.stored = []authz.Tuple{
		{User: principal, Relation: "granted_caller", Object: "published_mission:acme/recon"},
		{User: principal, Relation: "granted_caller", Object: "published_mission:acme/scan"},
		{User: "agent_principal:other", Relation: "granted_caller", Object: "published_mission:acme/recon"},
	}
	revoker := &fakePrincipalRevoker{}
	srv := newTestDaemonServer(t).WithIdPAdminClient(&fakeIDPClient{}).WithAuthorizer(az).WithPrincipalRevoker(revoker)

	_, err := srv.RevokeAgentIdentity(ctxWithTenantAdmin(context.Background(), "acme", "user-admin"),
		&tenantpb.RevokeAgentIdentityRequest{PrincipalId: principal})

	if err != nil {
		t.Fatalf("RevokeAgentIdentity: %v", err)
	}
	if len(revoker.calls) != 1 || revoker.calls[0] != "acme|"+principal {
		t.Errorf("revoker calls = %v", revoker.calls)
	}
	want := []authz.Tuple{
		{User: principal, Relation: "granted_caller", Object: "published_mission:acme/recon"},
		{User: principal, Relation: "granted_caller", Object: "published_mission:acme/scan"},
	}
	for _, w := range want {
		if !slices.Contains(az.deleted, w) {
			t.Errorf("the grant %v was not deleted: %v", w, az.deleted)
		}
	}
	if slices.Contains(az.deleted, authz.Tuple{User: "agent_principal:other", Relation: "granted_caller", Object: "published_mission:acme/recon"}) {
		t.Error("the grant of another identity was deleted")
	}
}

// When the Capability Grant revoke fails, nothing else is revoked, so the caller
// can retry and no identity is half revoked.
func TestRevokeAgentIdentity_AFailedGrantRevokeRevokesNothingElse(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	az := newFakeAuthorizer().allow("tenant:acme", "belongs_to", "agent_principal:some-uuid")
	for name, srv := range map[string]*DaemonServer{
		"the store fails": newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az).
			WithPrincipalRevoker(&fakePrincipalRevoker{err: errors.New("db down")}),
		"no store": newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az),
	} {
		_, err := srv.RevokeAgentIdentity(ctxWithTenantAdmin(context.Background(), "acme", "user-admin"),
			&tenantpb.RevokeAgentIdentityRequest{PrincipalId: "agent_principal:some-uuid"})
		if status.Code(err) != codes.Internal && status.Code(err) != codes.Unavailable {
			t.Errorf("%s: code = %v, want Internal or Unavailable", name, status.Code(err))
		}
	}
	if len(fakeidp.deleteCalls) != 0 {
		t.Errorf("the IdP account was deleted after a failed grant revoke: %d calls", len(fakeidp.deleteCalls))
	}
}

// A failed read of the inbound grants leaves the IdP account in place.
func TestRevokeAgentIdentity_AFailedGrantReadRevokesNoAccount(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	az := newFakeAuthorizer().allow("tenant:acme", "belongs_to", "agent_principal:some-uuid")
	az.readErr = errors.New("fga down")
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az).WithPrincipalRevoker(&fakePrincipalRevoker{})

	_, err := srv.RevokeAgentIdentity(ctxWithTenantAdmin(context.Background(), "acme", "user-admin"),
		&tenantpb.RevokeAgentIdentityRequest{PrincipalId: "agent_principal:some-uuid"})

	if status.Code(err) != codes.Internal || len(fakeidp.deleteCalls) != 0 {
		t.Errorf("code = %v, delete calls = %d", status.Code(err), len(fakeidp.deleteCalls))
	}
}
