// Package api — get_mission_graph.go implements DaemonService.GetMissionGraph.
//
// GetMissionGraph projects a mission definition (the pure work DAG) into the
// renderable MissionGraph the dashboard draws: typed nodes, data-flow edges,
// derived entry/exit, and per-node positions. The daemon computes the topology
// and a deterministic auto-layout, then overlays any saved layout from the
// layout store so hand-arranged positions win. Presentation only — nothing here
// affects mission execution.
//
// Spec: MissionGraph epic (sdk#278, gibson#598).
package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/gibson/internal/mission"
	"github.com/zeroroot-ai/gibson/internal/mission/graph"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// GetMissionGraph implements DaemonServiceServer.GetMissionGraph.
func (s *DaemonServer) GetMissionGraph(ctx context.Context, req *daemonpb.GetMissionGraphRequest) (*daemonpb.GetMissionGraphResponse, error) {
	if req.GetMissionDefinitionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_definition_id is required")
	}

	store, release, err := s.tenantMissionStore(ctx, "GetMissionGraph")
	if err != nil {
		return nil, err
	}
	defer release()

	def, err := store.GetDefinitionByID(ctx, req.GetMissionDefinitionId())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "GetMissionGraph: definition lookup failed: %v", err)
	}
	if def == nil {
		return nil, status_grpc.Errorf(codes.NotFound, "mission definition %q not found", req.GetMissionDefinitionId())
	}

	layout, err := store.GetLayout(ctx, req.GetMissionDefinitionId())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "GetMissionGraph: layout lookup failed: %v", err)
	}

	g, err := graph.Project(def, layout)
	if err != nil {
		var ve *graph.ValidationError
		if errors.As(err, &ve) {
			// A structurally-invalid mission is a bad definition, not a server
			// fault — surface it so the author can fix the DAG.
			return nil, status_grpc.Errorf(codes.FailedPrecondition, "mission definition is not a valid graph: %v", ve)
		}
		return nil, status_grpc.Errorf(codes.Internal, "GetMissionGraph: projection failed: %v", err)
	}

	return &daemonpb.GetMissionGraphResponse{Graph: g}, nil
}

// tenantMissionStore resolves the calling tenant and returns a conn-bound
// mission store plus a release func. Shared by the MissionGraph + layout
// handlers. The op name is used in error messages.
func (s *DaemonServer) tenantMissionStore(ctx context.Context, op string) (*mission.ConnBoundMissionStore, func(), error) {
	if s.poolGetter == nil {
		return nil, nil, status_grpc.Errorf(codes.Unavailable, "%s: data-plane pool not configured", op)
	}
	pool := s.poolGetter()
	if pool == nil {
		return nil, nil, status_grpc.Errorf(codes.Unavailable, "%s: data-plane pool not yet ready", op)
	}
	tenantID, ok := auth.TenantFromContext(ctx)
	if !ok || tenantID.IsZero() {
		return nil, nil, status_grpc.Errorf(codes.PermissionDenied, "%s: missing tenant in context", op)
	}
	conn, connErr := pool.For(ctx, tenantID)
	if connErr != nil {
		return nil, nil, datapool.MapPoolError(connErr)
	}
	return mission.NewConnBoundMissionStore(conn.Redis), conn.Release, nil
}
