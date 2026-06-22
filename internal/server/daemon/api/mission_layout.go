// Package api — mission_layout.go implements the DaemonService layout-store
// RPCs: GetMissionLayout and SaveMissionLayout.
//
// The layout store is separate from the mission definition; saving a layout
// never mutates the mission work-schema. Keyed by mission_definition_id.
//
// Spec: MissionGraph epic (sdk#278, gibson#598).
package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// GetMissionLayout implements DaemonServiceServer.GetMissionLayout.
func (s *DaemonServer) GetMissionLayout(ctx context.Context, req *daemonpb.GetMissionLayoutRequest) (*daemonpb.GetMissionLayoutResponse, error) {
	if req.GetMissionDefinitionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_definition_id is required")
	}

	store, release, err := s.tenantMissionStore(ctx, "GetMissionLayout")
	if err != nil {
		return nil, err
	}
	defer release()

	layout, err := store.GetLayout(ctx, req.GetMissionDefinitionId())
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "GetMissionLayout: store get failed: %v", err)
	}
	if layout == nil {
		// No saved layout yet — return an empty layout (empty version) rather
		// than NotFound, so the renderer falls back to auto-layout cleanly.
		layout = &daemonpb.MissionLayout{MissionDefinitionId: req.GetMissionDefinitionId()}
	}
	return &daemonpb.GetMissionLayoutResponse{Layout: layout}, nil
}

// SaveMissionLayout implements DaemonServiceServer.SaveMissionLayout.
func (s *DaemonServer) SaveMissionLayout(ctx context.Context, req *daemonpb.SaveMissionLayoutRequest) (*daemonpb.SaveMissionLayoutResponse, error) {
	layout := req.GetLayout()
	if layout == nil || layout.GetMissionDefinitionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "layout.mission_definition_id is required")
	}

	store, release, err := s.tenantMissionStore(ctx, "SaveMissionLayout")
	if err != nil {
		return nil, err
	}
	defer release()

	version, err := store.SaveLayout(ctx, layout, req.GetExpectedVersion())
	if err != nil {
		if errors.Is(err, mission.ErrLayoutConflict) {
			return nil, status_grpc.Error(codes.Aborted, "mission layout changed since it was read; reload and retry")
		}
		return nil, status_grpc.Errorf(codes.Internal, "SaveMissionLayout: store save failed: %v", err)
	}
	return &daemonpb.SaveMissionLayoutResponse{Version: version}, nil
}
