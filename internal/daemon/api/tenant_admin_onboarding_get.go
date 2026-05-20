// Package api — tenant_admin_onboarding_get.go implements
// TenantAdminService.GetOnboardingState.
//
// Relocated to new service per admin-services-completion spec.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
)

// GetOnboardingState returns the current onboarding state for a tenant.
//
// Returns codes.Unimplemented if the onboarding store is not configured.
func (s *DaemonServer) GetOnboardingState(ctx context.Context, req *tenantv1.GetOnboardingStateRequest) (*tenantv1.GetOnboardingStateResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.onboardingStore == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "onboarding service not configured")
	}

	currentStep, completedSteps, setupTasks, completedAt, err := s.onboardingStore.GetState(ctx, req.TenantId)
	if err != nil {
		s.logger.Error("failed to get onboarding state", "tenant_id", req.TenantId, "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "failed to get onboarding state: %v", err)
	}

	return &tenantv1.GetOnboardingStateResponse{
		CurrentStep:    currentStep,
		CompletedSteps: completedSteps,
		SetupTasks:     setupTasks,
		CompletedAt:    completedAt,
	}, nil
}
