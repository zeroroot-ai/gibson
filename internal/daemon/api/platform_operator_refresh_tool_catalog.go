// Package api — platform_operator_refresh_tool_catalog.go implements
// PlatformOperatorService.RefreshToolCatalog.
//
// Relocated to new service per admin-services-completion spec.
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	platformv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/platform/v1"
)

// RefreshToolCatalog triggers an immediate refresh of the sandboxed-tool
// catalog. Bypasses the scheduled interval — useful for CI to publish a
// new tool-runner image and immediately surface its parsers to the orchestrator.
//
// Only works on the replica currently holding the refresh leader lease;
// followers accept the call but defer to the leader's next scheduled tick.
// Requires the "platform_operator" FGA relation on system_tenant:_system.
func (s *DaemonServer) RefreshToolCatalog(ctx context.Context, req *platformv1.RefreshToolCatalogRequest) (*platformv1.RefreshToolCatalogResponse, error) {
	queued, msg, err := s.daemon.RefreshToolCatalog(ctx)
	if err != nil {
		s.logger.Error("tool catalog refresh signal failed", "error", err)
		return nil, status_grpc.Errorf(codes.Internal, "refresh tool catalog: %v", err)
	}
	return &platformv1.RefreshToolCatalogResponse{Queued: queued, Message: msg}, nil
}
