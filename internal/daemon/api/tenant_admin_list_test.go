package api

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/idp"
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

	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "user-admin")

	resp, err := srv.ListAgentIdentities(ctx, &tenantpb.ListAgentIdentitiesRequest{})
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(resp.Identities) != 2 {
		t.Fatalf("got %d identities, want 2", len(resp.Identities))
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

	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
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
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
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
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)
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
