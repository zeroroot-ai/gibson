// Package api — tenant_admin_onboarding_update.go implements
// TenantAdminService.UpdateOnboardingState.
//
// Relocated to new service per admin-services-completion spec.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// UpdateOnboardingState advances or modifies the onboarding state for a tenant.
//
// Returns codes.Unimplemented if the onboarding store is not configured.
//
// Cross-tenant guard: request tenant_id must match context tenant (matches
// the TenantAdminService pattern used by the langfuse handlers).
//
// gibsoncheck:allow tenant-from-request — TenantAdminService RPCs take the
// target tenant in the request body; the inline `auth.TenantStringFromContext(ctx)
// != req.TenantId` guard plus FGA's tenant_admin relation at ext-authz cover
// the cross-tenant case.
func (s *DaemonServer) UpdateOnboardingState(ctx context.Context, req *tenantv1.UpdateOnboardingStateRequest) (*tenantv1.UpdateOnboardingStateResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Cross-tenant guard: prevent tenant-A from modifying tenant-B's onboarding state.
	if auth.TenantStringFromContext(ctx) != req.TenantId {
		return nil, status_grpc.Error(codes.PermissionDenied, "tenant mismatch")
	}

	if s.onboardingStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "onboarding service not configured")
	}

	if err := s.onboardingStore.UpdateState(ctx, req.TenantId, req.CurrentStep, req.CompletedSteps, req.SetupTasks); err != nil {
		s.logger.Error("failed to update onboarding state", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to update onboarding state: %v", err)
	}

	s.logger.Info("onboarding state updated via RPC", "tenant_id", req.TenantId)
	return &tenantv1.UpdateOnboardingStateResponse{}, nil
}
