// Package api — server_tenant_provisioning_status.go
//
// Customer/dashboard-facing reads of the daemon's tenant-status mirror
// (dashboard#855). GetTenantProvisioningStatus (TenantService) serves the
// signup + tenant-status surfaces; CheckTenantSlugAvailable (SignupService)
// serves the pre-signup slug-uniqueness probe. Both read only the daemon's own
// Postgres — never Kubernetes (ADR-0023).
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// GetTenantProvisioningStatus returns the daemon's mirror of the caller
// tenant's Tenant-CR provisioning status. The tenant is resolved from the
// caller identity (ext-authz tenant_from_identity deriver), so a tenant can only
// read its own row — there is no tenant_id in the request and thus no
// cross-tenant read surface.
//
// Returns found=false (zero fields) when the operator has not yet reported a
// status for the tenant, which the dashboard treats as "still provisioning"
// (matching its prior K8sNotFound branch).
func (s *DaemonServer) GetTenantProvisioningStatus(ctx context.Context, _ *tenantv1.GetTenantProvisioningStatusRequest) (*tenantv1.GetTenantProvisioningStatusResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, "no tenant in caller context")
	}

	db := s.entitlementsDB()
	if db == nil {
		return nil, status_grpc.Error(codes.Unavailable, "platform Postgres not configured")
	}

	row, err := s.getTenantStatus(ctx, db, tenantID)
	if err != nil {
		s.logger.Error("failed to read tenant status", "tenant_id", tenantID, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to read tenant status: %v", err)
	}
	if row == nil {
		return &tenantv1.GetTenantProvisioningStatusResponse{Found: false}, nil
	}
	return &tenantv1.GetTenantProvisioningStatusResponse{
		Found:            true,
		Phase:            row.Phase,
		Ready:            row.Ready,
		ZitadelOrgId:     row.ZitadelOrgID,
		DataPlaneReady:   row.DataPlaneReady,
		OwnerMemberReady: row.OwnerMemberReady,
	}, nil
}

// CheckTenantSlugAvailable answers whether a workspace slug is free to claim,
// served from the daemon's own state — the pending-provisioning queue (in-flight
// self-serve signups) UNION the tenant-status mirror (provisioned tenants). The
// daemon never reads Kubernetes (ADR-0023). Unauthenticated (pre-tenant), like
// Signup; returns only a boolean availability bit.
func (s *DaemonServer) CheckTenantSlugAvailable(ctx context.Context, req *tenantv1.CheckTenantSlugAvailableRequest) (*tenantv1.CheckTenantSlugAvailableResponse, error) {
	if req.GetSlug() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "slug required")
	}

	db := s.entitlementsDB()
	if db == nil {
		return nil, status_grpc.Error(codes.Unavailable, "platform Postgres not configured")
	}

	// A pending/claimed/done provisioning row means a self-serve signup already
	// grabbed this slug (the operator may not have created the Tenant CR yet).
	pending, err := s.pendingTenantExists(ctx, db, req.GetSlug())
	if err != nil {
		s.logger.Error("failed to check pending provisioning for slug", "slug", req.GetSlug(), "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to check slug availability: %v", err)
	}
	if pending {
		return &tenantv1.CheckTenantSlugAvailableResponse{Available: false}, nil
	}

	// A tenant_status row means the tenant is (being) provisioned.
	provisioned, err := s.tenantStatusExists(ctx, db, req.GetSlug())
	if err != nil {
		s.logger.Error("failed to check tenant status for slug", "slug", req.GetSlug(), "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to check slug availability: %v", err)
	}
	return &tenantv1.CheckTenantSlugAvailableResponse{Available: !provisioned}, nil
}
