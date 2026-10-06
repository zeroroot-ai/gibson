// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// mission_rewind.go serves the two RPCs of a rewind (ADR-0170, gibson#804).
//
// A checkpoint is the end of a node in a mission run. A rewind starts a new
// run at the node of a checkpoint, with the earlier run as its parent, and
// deletes nothing. Whoever may run a mission may rewind it: the registry
// gives RewindMission the same tenant writer relation as RunMission.

// GetMissionCheckpoints returns the node ends of a mission run.
func (s *DaemonServer) GetMissionCheckpoints(ctx context.Context, req *daemonpb.GetMissionCheckpointsRequest) (*daemonpb.GetMissionCheckpointsResponse, error) {
	if req.GetMissionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_id is required")
	}
	cps, err := s.daemon.GetMissionCheckpoints(ctx, req.GetMissionId())
	if err != nil {
		return nil, preserveStatus(err, "get mission checkpoints")
	}
	out := make([]*daemonpb.NodeCheckpoint, 0, len(cps))
	for _, cp := range cps {
		nc := &daemonpb.NodeCheckpoint{
			CheckpointId:     cp.CheckpointID,
			NodeId:           cp.NodeID,
			TimelinePosition: cp.TimelinePosition,
		}
		if cp.SnapshotID != "" {
			id := cp.SnapshotID
			nc.SnapshotId = &id
		}
		out = append(out, nc)
	}
	return &daemonpb.GetMissionCheckpointsResponse{Checkpoints: out}, nil
}

// RewindMission starts a new mission run at a checkpoint of an earlier run.
func (s *DaemonServer) RewindMission(ctx context.Context, req *daemonpb.RewindMissionRequest) (*daemonpb.RewindMissionResponse, error) {
	if req.GetMissionId() == "" || req.GetCheckpointId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "mission_id and checkpoint_id are required")
	}
	if req.Instruction != nil && req.GetInstruction() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "instruction must not be empty when it is set")
	}
	newID, err := s.daemon.RewindMission(ctx, RewindRequest{
		MissionID:      req.GetMissionId(),
		CheckpointID:   req.GetCheckpointId(),
		Instruction:    req.Instruction,
		IdempotencyKey: req.GetIdempotencyKey(),
	})
	if err != nil {
		s.logger.Warn("mission rewind failed",
			"mission_id", req.GetMissionId(),
			"checkpoint_id", req.GetCheckpointId(),
			"error", err,
		)
		return nil, preserveStatus(err, "rewind mission")
	}
	s.emitRewindAudit(ctx, req.GetMissionId(), req.GetCheckpointId(), newID)
	return &daemonpb.RewindMissionResponse{MissionId: newID}, nil
}

// emitRewindAudit records who rewound which run to which checkpoint, and the
// run that the rewind started.
func (s *DaemonServer) emitRewindAudit(ctx context.Context, parentID, checkpointID, newID string) {
	tenantID := auth.TenantStringFromContext(ctx)
	subject := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		subject = id.Subject
	}
	s.logger.Info("audit: mission.rewound",
		"event_kind", "mission.rewound",
		"tenant_id", tenantID,
		"mission_id", newID,
		"parent_mission_id", parentID,
		"parent_checkpoint_id", checkpointID,
		"caller_subject", subject,
	)
	if s.tenantAdminAuditWriter != nil {
		meta, err := json.Marshal(map[string]string{
			"parent_mission_id":    parentID,
			"parent_checkpoint_id": checkpointID,
		})
		if err == nil {
			s.tenantAdminAuditWriter.Log(audit.Event{
				TenantID:   tenantID,
				ActorID:    subject,
				ActorType:  "user",
				Action:     "mission.rewound",
				TargetType: "mission",
				TargetID:   newID,
				Metadata:   meta,
			})
		}
	}
}
