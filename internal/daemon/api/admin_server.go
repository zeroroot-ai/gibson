// Package api — admin_server.go
//
// DaemonAdminServer implements gibson.daemon.admin.v1.DaemonAdminService —
// the admin/writer-relation RPC surface extracted from the OSS
// gibson.daemon.v1.DaemonService by slice gibson#227. The OSS DaemonService
// retains member/can_use RPCs; this private platform-sdk surface carries
// the four admin-tier writers:
//
//   - StartComponent
//   - StopComponent
//   - BuildComponent
//   - CreateMissionDefinition
//
// The adapter delegates each call to the same internal DaemonInterface
// methods the OSS DaemonServer uses, so business logic stays in one
// place. The wire types differ for CreateMissionDefinition: the
// platform-sdk request carries `bytes definition_serialized = 1` (a
// wire-encoded gibson.mission.v1.MissionDefinition from the OSS SDK)
// instead of a nested message. The adapter Unmarshals back into the
// OSS MissionDefinition before forwarding. The Start/Stop/Build wire
// types are structurally identical; the adapter constructs the
// platform-sdk-typed responses directly.
//
// Parent PRD: zero-day-ai/.github#101.
// Refs: platform-sdk PRs #7/#8, gibson PRs #226/#227/#233, sdk#105.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	daemonadminv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/daemon/admin/v1"
	missionpb "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// DaemonAdminServer wraps the OSS DaemonServer to expose the admin/writer
// RPC surface published by platform-sdk. It owns no state of its own —
// every call delegates to the wrapped DaemonServer (which in turn talks
// to DaemonInterface).
type DaemonAdminServer struct {
	daemonadminv1.UnimplementedDaemonAdminServiceServer

	inner  *DaemonServer
	logger *slog.Logger
}

// NewDaemonAdminServer constructs a DaemonAdminServer that wraps an
// existing DaemonServer. Caller passes the same DaemonServer instance
// that handles DaemonService RPCs so admin and member handlers share
// the same daemon orchestration state.
func NewDaemonAdminServer(inner *DaemonServer, logger *slog.Logger) *DaemonAdminServer {
	if logger == nil {
		logger = slog.Default()
	}
	return &DaemonAdminServer{
		inner:  inner,
		logger: logger,
	}
}

// StartComponent delegates to DaemonInterface.StartComponent with the same
// argument shape as DaemonService.StartComponent. The platform-sdk request
// type is wire-equivalent to the OSS one (same field numbers, names, and
// types) — the only difference is the package, which is the whole point
// of the split.
func (s *DaemonAdminServer) StartComponent(ctx context.Context, req *daemonadminv1.StartComponentRequest) (*daemonadminv1.StartComponentResponse, error) {
	if req.GetKind() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.GetName() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}
	if req.GetKind() != "agent" && req.GetKind() != "tool" && req.GetKind() != "plugin" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "invalid component kind: %s (must be agent, tool, or plugin)", req.GetKind())
	}

	result, err := s.inner.daemon.StartComponent(ctx, req.GetKind(), req.GetName())
	if err != nil {
		s.logger.Error("failed to start component", "error", err, "kind", req.GetKind(), "name", req.GetName())
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.GetName())
		}
		if strings.Contains(err.Error(), "already running") {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "component '%s' is already running", req.GetName())
		}
		return nil, status_grpc.Errorf(codes.Internal, "failed to start component: %v", err)
	}

	return &daemonadminv1.StartComponentResponse{
		Success: true,
		Pid:     int32(result.PID),
		Port:    int32(result.Port),
		Message: fmt.Sprintf("Component '%s' started successfully", req.GetName()),
		LogPath: result.LogPath,
	}, nil
}

// StopComponent delegates to DaemonInterface.StopComponent.
func (s *DaemonAdminServer) StopComponent(ctx context.Context, req *daemonadminv1.StopComponentRequest) (*daemonadminv1.StopComponentResponse, error) {
	if req.GetKind() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.GetName() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	result, err := s.inner.daemon.StopComponent(ctx, req.GetKind(), req.GetName(), req.GetForce())
	if err != nil {
		s.logger.Error("failed to stop component", "error", err, "kind", req.GetKind(), "name", req.GetName())
		if strings.Contains(err.Error(), "not found") {
			return nil, status_grpc.Errorf(codes.NotFound, "component '%s' not found", req.GetName())
		}
		return nil, status_grpc.Errorf(codes.Internal, "failed to stop component: %v", err)
	}

	return &daemonadminv1.StopComponentResponse{
		Success:      true,
		StoppedCount: int32(result.StoppedCount),
		TotalCount:   int32(result.TotalCount),
		Message:      fmt.Sprintf("stopped %d/%d processes", result.StoppedCount, result.TotalCount),
	}, nil
}

// BuildComponent delegates to DaemonInterface.BuildComponent.
func (s *DaemonAdminServer) BuildComponent(ctx context.Context, req *daemonadminv1.BuildComponentRequest) (*daemonadminv1.BuildComponentResponse, error) {
	if req.GetKind() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component kind is required")
	}
	if req.GetName() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "component name is required")
	}

	result, err := s.inner.daemon.BuildComponent(ctx, req.GetKind(), req.GetName())
	if err != nil {
		s.logger.Error("failed to build component", "error", err, "kind", req.GetKind(), "name", req.GetName())
		return nil, status_grpc.Errorf(codes.Internal, "failed to build component: %v", err)
	}

	return &daemonadminv1.BuildComponentResponse{
		Success: true,
		Stdout:  result.Stdout,
		Stderr:  result.Stderr,
		Message: fmt.Sprintf("Component '%s' built successfully", req.GetName()),
	}, nil
}

// CreateMissionDefinition unmarshals the OSS gibson.mission.v1.MissionDefinition
// from the platform-sdk request's `definition_serialized: bytes` slot and
// delegates to DaemonInterface.CreateMissionDefinition. The platform-sdk
// response carries a flat subset of the OSS response (id, name, version) so
// callers that only need to chain a CreateMission do not have to pull the
// full MissionDefinitionInfo wire shape into platform-sdk.
func (s *DaemonAdminServer) CreateMissionDefinition(ctx context.Context, req *daemonadminv1.CreateMissionDefinitionRequest) (*daemonadminv1.CreateMissionDefinitionResponse, error) {
	raw := req.GetDefinitionSerialized()
	if len(raw) == 0 {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "definition_serialized is required")
	}

	def := &missionpb.MissionDefinition{}
	if err := proto.Unmarshal(raw, def); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "definition_serialized unmarshal failed: %v", err)
	}
	if def.GetName() == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "definition name is required")
	}

	result, err := s.inner.daemon.CreateMissionDefinition(ctx, CreateMissionDefinitionData{Definition: def})
	if err != nil {
		s.logger.Error("failed to create mission definition", "error", err, "name", def.GetName())
		if strings.Contains(err.Error(), "already exists") {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "%v", err)
		}
		return nil, preserveStatus(err, "failed to create mission definition")
	}

	s.logger.Info("mission definition created",
		"mission_definition_id", result.MissionDefinitionID,
		"name", result.Info.Name,
	)

	return &daemonadminv1.CreateMissionDefinitionResponse{
		MissionDefinitionId: result.MissionDefinitionID,
		Name:                result.Info.Name,
		Version:             result.Info.Version,
	}, nil
}
