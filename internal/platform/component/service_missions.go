package component

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// CreateMission creates a new sub-mission.
func (s *ComponentServiceServer) CreateMission(ctx context.Context, req *componentpb.CreateMissionRequest) (*componentpb.CreateMissionResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	missionJSON, err := s.missionMgr.CreateMission(ctx, tenant, req.GetMissionDefinitionJson(), req.GetTargetId(), req.GetOptsJson())
	if err != nil {
		s.logger.Error("CreateMission failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "create failed: %v", err)
	}
	return &componentpb.CreateMissionResponse{MissionJson: missionJSON}, nil
}

// RunMission queues a mission for execution.
func (s *ComponentServiceServer) RunMission(ctx context.Context, req *componentpb.RunMissionRequest) (*componentpb.RunMissionResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	if err := s.missionMgr.RunMission(ctx, tenant, req.GetMissionId(), req.GetOptsJson()); err != nil {
		s.logger.Error("RunMission failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, status.Errorf(codes.Internal, "run failed: %v", err)
	}
	return &componentpb.RunMissionResponse{}, nil
}

// GetMissionStatus returns the current status of a mission.
func (s *ComponentServiceServer) GetMissionStatus(ctx context.Context, req *componentpb.GetMissionStatusRequest) (*componentpb.GetMissionStatusResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	statusJSON, err := s.missionMgr.GetMissionStatus(ctx, tenant, req.GetMissionId())
	if err != nil {
		s.logger.Error("GetMissionStatus failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, status.Errorf(codes.Internal, "status query failed: %v", err)
	}
	return &componentpb.GetMissionStatusResponse{StatusJson: statusJSON}, nil
}

// WaitMission blocks until a mission completes or the timeout expires.
func (s *ComponentServiceServer) WaitMission(ctx context.Context, req *componentpb.WaitMissionRequest) (*componentpb.WaitMissionResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	resultJSON, err := s.missionMgr.WaitForMission(ctx, tenant, req.GetMissionId(), req.GetTimeoutMs())
	if err != nil {
		s.logger.Error("WaitMission failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, status.Errorf(codes.Internal, "wait failed: %v", err)
	}
	return &componentpb.WaitMissionResponse{ResultJson: resultJSON}, nil
}

// ListMissions returns missions matching the given filter.
func (s *ComponentServiceServer) ListMissions(ctx context.Context, req *componentpb.ListMissionsRequest) (*componentpb.ListMissionsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	missionsJSON, err := s.missionMgr.ListMissions(ctx, tenant, req.GetFilterJson())
	if err != nil {
		s.logger.Error("ListMissions failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "list failed: %v", err)
	}
	return &componentpb.ListMissionsResponse{MissionsJson: missionsJSON}, nil
}

// CancelMission requests cancellation of a running mission.
func (s *ComponentServiceServer) CancelMission(ctx context.Context, req *componentpb.CancelMissionRequest) (*componentpb.CancelMissionResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	if err := s.missionMgr.CancelMission(ctx, tenant, req.GetMissionId()); err != nil {
		s.logger.Error("CancelMission failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, status.Errorf(codes.Internal, "cancel failed: %v", err)
	}
	return &componentpb.CancelMissionResponse{}, nil
}

// GetMissionResults returns the final results of a completed mission.
func (s *ComponentServiceServer) GetMissionResults(ctx context.Context, req *componentpb.GetMissionResultsRequest) (*componentpb.GetMissionResultsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	resultJSON, err := s.missionMgr.GetMissionResults(ctx, tenant, req.GetMissionId())
	if err != nil {
		s.logger.Error("GetMissionResults failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, status.Errorf(codes.Internal, "results query failed: %v", err)
	}
	return &componentpb.GetMissionResultsResponse{ResultJson: resultJSON}, nil
}

// GetMissionRunHistory returns summaries of previous mission runs.
func (s *ComponentServiceServer) GetMissionRunHistory(ctx context.Context, req *componentpb.GetMissionRunHistoryRequest) (*componentpb.GetMissionRunHistoryResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return nil, status.Error(codes.Unimplemented, "mission management not configured")
	}
	runsJSON, err := s.missionMgr.GetMissionRunHistory(ctx, tenant, req.GetWorkId())
	if err != nil {
		s.logger.Error("GetMissionRunHistory failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "history query failed: %v", err)
	}
	return &componentpb.GetMissionRunHistoryResponse{RunsJson: runsJSON}, nil
}
