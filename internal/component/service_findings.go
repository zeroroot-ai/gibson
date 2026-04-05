package component

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zero-day-ai/gibson/internal/auth"
)

// GetFindings queries previously submitted findings with optional filters.
func (s *ComponentServiceServer) GetFindings(ctx context.Context, req *componentpb.GetFindingsRequest) (*componentpb.GetFindingsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.findingQuerier == nil {
		return nil, status.Error(codes.Unimplemented, "finding queries not configured")
	}
	findingsJSON, err := s.findingQuerier.GetFindings(ctx, tenant, req.GetFilterJson())
	if err != nil {
		s.logger.Error("GetFindings failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "query failed: %v", err)
	}
	return &componentpb.GetFindingsResponse{FindingsJson: findingsJSON}, nil
}

// GetRunFindings queries findings scoped to a specific mission run or across all runs.
func (s *ComponentServiceServer) GetRunFindings(ctx context.Context, req *componentpb.GetRunFindingsRequest) (*componentpb.GetRunFindingsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.findingQuerier == nil {
		return nil, status.Error(codes.Unimplemented, "finding queries not configured")
	}
	findingsJSON, err := s.findingQuerier.GetRunFindings(ctx, tenant, req.GetWorkId(), req.GetScope(), req.GetFilterJson())
	if err != nil {
		s.logger.Error("GetRunFindings failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "query failed: %v", err)
	}
	return &componentpb.GetRunFindingsResponse{FindingsJson: findingsJSON}, nil
}
