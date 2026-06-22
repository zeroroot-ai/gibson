package api

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestListAgentIdentities_HappyPath(t *testing.T) {
	now := time.Now().UTC()
	fakeidp := &fakeIDPClient{
		listFn: func(_ context.Context, _ idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			return &idp.ListServiceAccountsResponse{
				ServiceAccounts: []idp.ServiceAccount{
					{
						AccountID:   "user-1",
						Name:        "agent-acme-myagent",
						Role:        idp.RoleAgent,
						CreatedAt:   now,
						Description: "test agent",
					},
					{
						AccountID: "user-2",
						Name:      "tool-acme-mytool",
						Role:      idp.RoleTool,
						CreatedAt: now,
					},
				},
			}, nil
		},
	}

	az := newFakeAuthorizer().
		withObjects("tenant:acme", "belongs_to", "agent_principal", "agent_principal:user-1").
		withObjects("tenant:acme", "belongs_to", "tool_principal", "tool_principal:user-2")
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	resp, err := srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{})
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(resp.Identities) != 2 {
		t.Fatalf("got %d identities, want 2", len(resp.Identities))
	}
}

// TestListAgentIdentities_CrossTenantExcluded is the regression test for
// gibson#606. Machine users from all tenants share one IdP org, so the IdP
// listing is not tenant-scoped. Only principals FGA attributes to the caller's
// tenant may be returned — never another tenant's, and never via the username
// prefix.
func TestListAgentIdentities_CrossTenantExcluded(t *testing.T) {
	fakeidp := &fakeIDPClient{
		listFn: func(_ context.Context, _ idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			// The shared org contains this tenant's agent AND another tenant's.
			return &idp.ListServiceAccountsResponse{
				ServiceAccounts: []idp.ServiceAccount{
					{AccountID: "mine", Name: "agent-acme-mine", Role: idp.RoleAgent},
					{AccountID: "intruder", Name: "agent-evil-intruder", Role: idp.RoleAgent},
				},
			}, nil
		},
	}
	// FGA attributes only "mine" to tenant acme.
	az := newFakeAuthorizer().
		withObjects("tenant:acme", "belongs_to", "agent_principal", "agent_principal:mine")
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	resp, err := srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{})
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(resp.Identities) != 1 {
		t.Fatalf("got %d identities, want 1 (cross-tenant leak)", len(resp.Identities))
	}
	if resp.Identities[0].PrincipalId != "agent_principal:mine" {
		t.Errorf("leaked principal: got %q, want agent_principal:mine", resp.Identities[0].PrincipalId)
	}
}

// TestListAgentIdentities_FailsClosedWithoutAuthorizer ensures the handler
// refuses to enumerate the shared org when it cannot consult FGA to scope the
// results — fail closed rather than leak (gibson#606).
func TestListAgentIdentities_FailsClosedWithoutAuthorizer(t *testing.T) {
	fakeidp := &fakeIDPClient{
		listFn: func(_ context.Context, _ idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			t.Fatal("ListServiceAccounts must not be called when authorizer is absent")
			return nil, nil
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp) // no authorizer
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("got code %v, want Unavailable", status.Code(err))
	}
}

func TestListAgentIdentities_KindFilter(t *testing.T) {
	fakeidp := &fakeIDPClient{
		listFn: func(_ context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			// Return only tool when filter is set
			if req.RoleFilter == idp.RoleTool {
				return &idp.ListServiceAccountsResponse{
					ServiceAccounts: []idp.ServiceAccount{
						{AccountID: "tool-1", Name: "tool-acme-t1", Role: idp.RoleTool},
					},
				}, nil
			}
			return &idp.ListServiceAccountsResponse{}, nil
		},
	}

	az := newFakeAuthorizer().
		withObjects("tenant:acme", "belongs_to", "tool_principal", "tool_principal:tool-1")
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(az)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	resp, err := srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{
		KindFilter: tenantpb.PrincipalKind_PRINCIPAL_KIND_TOOL,
	})
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(resp.Identities) != 1 {
		t.Fatalf("got %d identities, want 1", len(resp.Identities))
	}
	if resp.Identities[0].Kind != tenantpb.PrincipalKind_PRINCIPAL_KIND_TOOL {
		t.Errorf("kind = %v, want TOOL", resp.Identities[0].Kind)
	}
}

func TestListAgentIdentities_PageSizeDefault(t *testing.T) {
	var capturedPageSize int
	fakeidp := &fakeIDPClient{
		listFn: func(_ context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			capturedPageSize = req.PageSize
			return &idp.ListServiceAccountsResponse{}, nil
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(newFakeAuthorizer())
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, _ = srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{PageSize: 0})
	if capturedPageSize != defaultPageSize {
		t.Errorf("pageSize = %d, want %d", capturedPageSize, defaultPageSize)
	}
}

func TestListAgentIdentities_PageSizeCappedAtMax(t *testing.T) {
	var capturedPageSize int
	fakeidp := &fakeIDPClient{
		listFn: func(_ context.Context, req idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
			capturedPageSize = req.PageSize
			return &idp.ListServiceAccountsResponse{}, nil
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp).WithAuthorizer(newFakeAuthorizer())
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, _ = srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{PageSize: 9999})
	if capturedPageSize != maxPageSize {
		t.Errorf("pageSize = %d, want %d (max)", capturedPageSize, maxPageSize)
	}
}

func TestListAgentIdentities_NoIdPConfigured(t *testing.T) {
	srv := newTestDaemonServer(t)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	_, err := srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("got code %v, want Unavailable", status.Code(err))
	}
}
