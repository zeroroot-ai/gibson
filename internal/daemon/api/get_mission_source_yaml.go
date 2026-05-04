// Package api — get_mission_source_yaml.go implements DaemonService.GetMissionSourceYAML.
//
// GetMissionSourceYAML returns the original YAML the dashboard cached on the
// mission record when it called CreateMission with a non-empty source_yaml field.
// Missions created programmatically (no source_yaml) return codes.NotFound — the
// caller should fall back to re-authoring from scratch.
//
// The handler lives on DaemonService (not ComponentService) per the Phase 1
// deviation from design.md D3: the dashboard already routes mission RPCs through
// DaemonService, and GetMissionSourceYAML fits there naturally.
//
// Spec: dashboard-neo4j-crud-removal (Phase 2, Task 7).
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// GetMissionSourceYAML implements DaemonServiceServer.GetMissionSourceYAML.
func (s *DaemonServer) GetMissionSourceYAML(ctx context.Context, req *daemonpb.GetMissionSourceYAMLRequest) (*daemonpb.GetMissionSourceYAMLResponse, error) {
	if req.GetMissionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_id is required")
	}

	if s.poolGetter == nil {
		return nil, status_grpc.Error(codes.Unavailable, "GetMissionSourceYAML: data-plane pool not configured")
	}
	pool := s.poolGetter()
	if pool == nil {
		return nil, status_grpc.Error(codes.Unavailable, "GetMissionSourceYAML: data-plane pool not yet ready")
	}

	// Resolve tenant from context — ext-authz populates this for all authenticated callers.
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, status_grpc.Error(codes.PermissionDenied, "GetMissionSourceYAML: missing tenant in context")
	}

	conn, connErr := pool.For(ctx, tenantID)
	if connErr != nil {
		return nil, datapool.MapPoolError(connErr)
	}
	defer conn.Release()

	missionID, err := types.ParseID(req.GetMissionId())
	if err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid mission_id: %v", err)
	}

	store := mission.NewConnBoundMissionStore(conn.Redis)
	m, err := store.Get(ctx, missionID)
	if err != nil {
		if mission.IsNotFoundError(err) {
			return nil, status_grpc.Errorf(codes.NotFound, "mission %s not found", req.GetMissionId())
		}
		return nil, status_grpc.Errorf(codes.Internal, "GetMissionSourceYAML: store get failed: %v", err)
	}

	// Verify tenant ownership (defence-in-depth on top of FGA ext-authz gate).
	if m.TenantID != "" && m.TenantID != tenantID.String() {
		return nil, status_grpc.Errorf(codes.NotFound, "mission %s not found", req.GetMissionId())
	}

	if m.SourceYAML == "" {
		// Programmatic-creation path: no YAML was captured.
		return nil, status_grpc.Errorf(codes.NotFound,
			"no cached YAML for mission %s — mission was created programmatically or predates source_yaml capture",
			req.GetMissionId())
	}

	// Build captured_at from mission CreatedAt (the YAML was captured at create time).
	var capturedAt *timestamppb.Timestamp
	if !m.CreatedAt.IsZero() {
		capturedAt = timestamppb.New(m.CreatedAt.Time)
	}

	return &daemonpb.GetMissionSourceYAMLResponse{
		Yaml:        m.SourceYAML,
		MissionName: m.Name,
		CapturedAt:  capturedAt,
	}, nil
}
