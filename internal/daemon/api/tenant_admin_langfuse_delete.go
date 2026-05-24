// Package api — tenant_admin_langfuse_delete.go implements
// TenantAdminService.DeleteTenantLangfuseCredentials.
//
// Relocated to new service per admin-services-completion spec.
// Security: adds inline cross-tenant guard before any side effect.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// DeleteTenantLangfuseCredentials removes the Langfuse project credentials for a tenant.
//
// Cross-tenant guard: request tenant_id must match context tenant.
//
// gibsoncheck:allow tenant-from-request — TenantAdminService RPCs take the
// target tenant in the request body; the inline `auth.TenantStringFromContext(ctx)
// != req.TenantId` guard plus FGA's tenant_admin relation at ext-authz cover
// the cross-tenant case.
func (s *DaemonServer) DeleteTenantLangfuseCredentials(ctx context.Context, req *tenantv1.DeleteTenantLangfuseCredentialsRequest) (*tenantv1.DeleteTenantLangfuseCredentialsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Cross-tenant guard: prevent tenant-A from deleting tenant-B's credentials.
	if auth.TenantStringFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "tenant mismatch")
	}

	if s.credentialHandler == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "credential handler not configured")
	}

	name := langfuseCredentialName(req.TenantId)

	existing, err := s.credentialHandler.GetByName(ctx, name)
	if err != nil {
		s.logger.Debug("langfuse credentials not found for deletion", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.NotFound, "langfuse credentials not found for tenant %q", req.TenantId)
	}

	if err := s.credentialHandler.Delete(ctx, existing.ID); err != nil {
		s.logger.Error("failed to delete langfuse credentials", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to delete langfuse credentials: %v", err)
	}

	s.logger.Info("langfuse credentials deleted", "tenant_id", req.TenantId)
	return &tenantv1.DeleteTenantLangfuseCredentialsResponse{}, nil
}
