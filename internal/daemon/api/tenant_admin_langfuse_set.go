// Package api — tenant_admin_langfuse_set.go implements
// TenantAdminService.SetTenantLangfuseCredentials.
//
// Relocated to new service per admin-services-completion spec.
// Security: adds inline cross-tenant guard before any side effect.
package api

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/types"
	tenantv1 "github.com/zero-day-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// SetTenantLangfuseCredentials stores or updates Langfuse project credentials for a tenant.
//
// Cross-tenant guard: request tenant_id must match context tenant.
//
// gibsoncheck:allow tenant-from-request — TenantAdminService RPCs take the
// target tenant in the request body; the inline `auth.TenantStringFromContext(ctx)
// != req.TenantId` guard plus FGA's tenant_admin relation at ext-authz cover
// the cross-tenant case.
func (s *DaemonServer) SetTenantLangfuseCredentials(ctx context.Context, req *tenantv1.SetTenantLangfuseCredentialsRequest) (*tenantv1.SetTenantLangfuseCredentialsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Cross-tenant guard: prevent tenant-A from modifying tenant-B's credentials.
	if auth.TenantStringFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "tenant mismatch")
	}

	if s.credentialHandler == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "credential handler not configured")
	}

	payload := langfuseCredentialPayload{
		PublicKey: req.PublicKey,
		SecretKey: req.SecretKey,
		Host:      req.Host,
		ProjectID: req.ProjectId,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("failed to marshal langfuse credential payload", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to encode langfuse credentials: %v", err)
	}

	name := langfuseCredentialName(req.TenantId)

	// Attempt update if credentials already exist; fall back to create.
	existing, err := s.credentialHandler.GetByName(ctx, name)
	if err == nil {
		apiKey := string(payloadJSON)
		_, updateErr := s.credentialHandler.Update(ctx, CredentialUpdateRequest{
			ID:     existing.ID,
			APIKey: &apiKey,
		})
		if updateErr != nil {
			s.logger.Error("failed to update langfuse credentials", "tenant_id", req.TenantId, "error", updateErr)
			return nil, status_grpc.Errorf(codes.Internal, "failed to update langfuse credentials: %v", updateErr)
		}
	} else {
		_, createErr := s.credentialHandler.Create(ctx, CredentialCreateRequest{
			Name:        name,
			Type:        types.CredentialTypeLangfuseProject,
			Provider:    "langfuse",
			APIKey:      string(payloadJSON),
			Description: fmt.Sprintf("Langfuse project credentials for tenant %s", req.TenantId),
		})
		if createErr != nil {
			s.logger.Error("failed to create langfuse credentials", "tenant_id", req.TenantId, "error", createErr)
			return nil, status_grpc.Errorf(codes.Internal, "failed to store langfuse credentials: %v", createErr)
		}
	}

	s.logger.Info("langfuse credentials stored", "tenant_id", req.TenantId)
	return &tenantv1.SetTenantLangfuseCredentialsResponse{}, nil
}
