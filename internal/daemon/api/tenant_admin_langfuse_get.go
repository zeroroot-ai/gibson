// Package api — tenant_admin_langfuse_get.go implements
// TenantAdminService.GetTenantLangfuseCredentials.
//
// Relocated to new service per admin-services-completion spec.
// Security: adds inline cross-tenant guard
// `auth.TenantStringFromContext(ctx) != req.TenantId` before any side effect.
package api

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// GetTenantLangfuseCredentials retrieves the Langfuse project credentials for a tenant.
// Returns NOT_FOUND if no credentials have been configured for the tenant.
//
// Cross-tenant guard: request tenant_id must match context tenant.
//
// gibsoncheck:allow tenant-from-request — TenantAdminService RPCs take the
// target tenant in the request body; the inline `auth.TenantStringFromContext(ctx)
// != req.TenantId` guard plus FGA's tenant_admin relation at ext-authz cover
// the cross-tenant case.
func (s *DaemonServer) GetTenantLangfuseCredentials(ctx context.Context, req *tenantv1.GetTenantLangfuseCredentialsRequest) (*tenantv1.GetTenantLangfuseCredentialsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Cross-tenant guard: prevent tenant-A from reading tenant-B's credentials.
	if auth.TenantStringFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "tenant mismatch")
	}

	if s.credentialHandler == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "credential handler not configured")
	}

	name := langfuseCredentialName(req.TenantId)

	_, decrypted, err := s.credentialHandler.GetDecrypted(ctx, name)
	if err != nil {
		s.logger.Debug("langfuse credentials not found", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.NotFound, "langfuse credentials not found for tenant %q", req.TenantId)
	}

	var payload langfuseCredentialPayload
	if err := json.Unmarshal([]byte(decrypted), &payload); err != nil {
		s.logger.Error("failed to unmarshal langfuse credential payload", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to decode langfuse credentials: %v", err)
	}

	return &tenantv1.GetTenantLangfuseCredentialsResponse{
		PublicKey: payload.PublicKey,
		SecretKey: payload.SecretKey,
		Host:      payload.Host,
		ProjectId: payload.ProjectID,
	}, nil
}
