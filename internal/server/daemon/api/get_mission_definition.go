// Package api — get_mission_definition.go implements DaemonService.GetMissionDefinition.
//
// GetMissionDefinition returns the full gibson.mission.v1.MissionDefinition proto for
// a single installed mission definition, looked up by name. Every author-facing field
// is returned: workspace, constraints, per-node retry/data/reuse policies, etc.
//
// Returns codes.NotFound when the name is not registered.
//
// Spec: mission-author-experience M5 (gibson#134).
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// GetMissionDefinition implements DaemonServiceServer.GetMissionDefinition.
func (s *DaemonServer) GetMissionDefinition(ctx context.Context, req *daemonpb.GetMissionDefinitionRequest) (*daemonpb.GetMissionDefinitionResponse, error) {
	if req.GetName() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "name is required")
	}

	if s.poolGetter == nil {
		return nil, status_grpc.Error(codes.Unavailable, "GetMissionDefinition: data-plane pool not configured")
	}
	pool := s.poolGetter()
	if pool == nil {
		return nil, status_grpc.Error(codes.Unavailable, "GetMissionDefinition: data-plane pool not yet ready")
	}

	// Resolve tenant from context — ext-authz populates this for all authenticated callers.
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, status_grpc.Error(codes.PermissionDenied, "GetMissionDefinition: missing tenant in context")
	}

	conn, connErr := pool.For(ctx, tenantID)
	if connErr != nil {
		return nil, datapool.MapPoolError(connErr)
	}
	defer conn.Release()

	store := mission.NewConnBoundMissionStore(conn.Redis)
	def, err := store.GetDefinition(ctx, req.GetName())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "GetMissionDefinition: store get failed: %v", err)
	}
	if def == nil {
		return nil, status_grpc.Errorf(codes.NotFound, "mission definition %q not found", req.GetName())
	}

	// Return the author's raw CUE source when present. Empty for definitions
	// registered before source persistence or without a source. gibson#504.
	cueSource, srcErr := store.GetDefinitionSource(ctx, req.GetName())
	if srcErr != nil {
		return nil, status_grpc.Errorf(codes.Internal, "GetMissionDefinition: source get failed: %v", srcErr)
	}

	return &daemonpb.GetMissionDefinitionResponse{
		MissionDefinitionId: def.GetId(),
		Definition:          def,
		CueSource:           cueSource,
	}, nil
}
