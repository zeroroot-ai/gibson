// Package api — platform_operator_impersonate.go implements
// PlatformOperatorService.ImpersonateTenant.
//
// Relocated to new service per admin-services-completion spec.
// Handler body is identical to the original; receiver type changes to
// satisfy PlatformOperatorServiceServer.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ImpersonateTenant issues a short-lived context token scoped to the target
// tenant for platform-operator use.
//
// Requires the "platform_operator" FGA relation on system_tenant:_system.
// Authorization is enforced by the Envoy + ext-authz layer; this handler
// validates the request parameters and issues the token.
//
// gibsoncheck:allow tenant-from-request — by design the caller's identity
// is a platform operator, NOT the target tenant; req.TenantId names the
// impersonation target. FGA enforces the platform_operator relation on
// system_tenant:_system at ext-authz before this handler runs.
func (s *DaemonServer) ImpersonateTenant(ctx context.Context, req *daemonoperatorv1.ImpersonateTenantRequest) (*daemonoperatorv1.ImpersonateTenantResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	// Extract caller identity for the audit trail.
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "not authenticated")
	}

	s.logger.Info("tenant impersonation started",
		"admin_subject", callerID.Subject,
		"target_tenant", req.TenantId,
	)

	// Emit audit event for every impersonation attempt regardless of outcome.
	if s.auditLogger != nil {
		s.auditLogger.Log(ctx, "tenants:impersonate", "tenant", req.TenantId, map[string]any{
			"admin_subject": callerID.Subject,
		})
	}

	// Issue a signed impersonation token if the issuer is wired.
	if s.impersonationIssuer == nil {
		return nil, status_grpc.Errorf(codes.Unimplemented, "impersonation service not configured")
	}

	token, err := s.impersonationIssuer.IssueToken(ctx, req.TenantId)
	if err != nil {
		s.logger.Error("failed to issue impersonation token",
			"target_tenant", req.TenantId,
			"error", err,
		)
		return nil, status_grpc.Errorf(codes.Internal, "failed to issue impersonation token: %v", err)
	}

	return &daemonoperatorv1.ImpersonateTenantResponse{
		Token: token,
	}, nil
}
