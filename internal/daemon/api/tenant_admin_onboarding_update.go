// Package api — tenant_admin_onboarding_update.go implements
// TenantAdminService.UpdateOnboardingState.
//
// Relocated to new service per admin-services-completion spec.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
)

// UpdateOnboardingState advances or modifies the onboarding state for a tenant.
//
// Returns codes.Unimplemented if the onboarding store is not configured.
func (s *DaemonServer) UpdateOnboardingState(ctx context.Context, req *tenantv1.UpdateOnboardingStateRequest) (*tenantv1.UpdateOnboardingStateResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
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
