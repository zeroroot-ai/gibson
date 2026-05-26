// Package api — update_mission_definition.go implements DaemonService.UpdateMissionDefinition.
//
// UpdateMissionDefinition replaces the content of an existing mission definition,
// preserving the server-assigned ID and original timestamps. The name field of
// the incoming definition is the lookup key.
//
// Returns codes.NotFound when the name is not registered.
// Spec: gibson#437.
package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/mission"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// UpdateMissionDefinition implements DaemonServiceServer.UpdateMissionDefinition.
func (s *DaemonServer) UpdateMissionDefinition(ctx context.Context, req *daemonpb.UpdateMissionDefinitionRequest) (*daemonpb.UpdateMissionDefinitionResponse, error) {
	if req.GetDefinition() == nil {
		return nil, status_grpc.Error(codes.InvalidArgument, "definition is required")
	}
	if req.GetDefinition().GetName() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "definition name is required")
	}

	result, err := s.daemon.UpdateMissionDefinition(ctx, UpdateMissionDefinitionData{
		Definition: req.GetDefinition(),
	})
	if err != nil {
		if errors.Is(err, mission.ErrDefinitionNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "mission definition %q not found", req.GetDefinition().GetName())
		}
		return nil, status_grpc.Errorf(codes.Internal, "UpdateMissionDefinition: %v", err)
	}

	s.logger.Info("mission definition updated",
		"mission_definition_id", result.MissionDefinitionID,
		"name", req.GetDefinition().GetName(),
	)

	return &daemonpb.UpdateMissionDefinitionResponse{
		MissionDefinitionId: result.MissionDefinitionID,
	}, nil
}
