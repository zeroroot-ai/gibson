// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// service_missions.go: the mission surface an off-cluster component reaches
// through ComponentService (gibson#1358, slice 2 of gibson#1186 slice C).
//
// Every RPC here is gated on capname.MissionOriginate — including the reads.
// That is deliberate and worth stating, because gating a status query on an
// "originate" bit looks over-strict at first glance: these RPCs exist so a
// component can run a mission IT started, and a component that may not start
// one has no mission of its own to ask about. Reading another mission's
// status is the dashboard's job, on the user's surface, under the user's
// authorization. One bit, one story.
//
// The authority-bearing inputs never come from the request payload:
//
//	tenant   auth.TenantStringFromContext — the verified identity's tenant.
//	parent   resolved from the caller's work item through
//	         MissionContextResolver, which refuses a work id belonging to
//	         another tenant (gibson#1250) and answers "" instead.
//	grant    the id of the ACTIVE grant that carried mission:originate,
//	         returned by the same lookup that authorized the call.
//
// A caller can therefore name a work id it does not own, or a tenant, or a
// grant, and change nothing about what happens.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/capname"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// missionCall performs the two checks every mission RPC shares — a verified
// tenant and the mission:originate grant — and hands back both, so a handler
// body is the operation and nothing else.
func (s *ComponentServiceServer) missionCall(ctx context.Context) (tenant, grantID string, err error) {
	tenant = auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return "", "", status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.missionMgr == nil {
		return "", "", status.Error(codes.Unavailable,
			"mission origination is not available: the daemon has no per-tenant mission store configured")
	}
	grantID, err = s.requireCapability(ctx, tenant, capname.MissionOriginate)
	if err != nil {
		return "", "", err
	}
	return tenant, grantID, nil
}

// missionError passes a status error through unchanged and wraps anything
// else as Internal. The seam's implementation lives in the daemon package
// and already speaks gRPC statuses for the cases it can distinguish
// (NotFound, InvalidArgument, ResourceExhausted, PermissionDenied); this
// keeps those from being flattened into Internal on the way out.
func missionError(err error, fallback string) error {
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		//nolint:wrapcheck // deliberately re-returning the seam's own status
		return err
	}
	return status.Errorf(codes.Internal, "%s: %v", fallback, err)
}

// CreateMission originates a new mission on behalf of the calling component.
//
// The child's budget is clamped to what the parent mission has left and
// reserved against it, its target set must be a subset of the parent's, and
// its lineage is recorded at creation — see internal/engine/mission's
// originate.go for the policy and why a caller with no parent mission is
// refused rather than given an unbounded one.
func (s *ComponentServiceServer) CreateMission(ctx context.Context, req *componentpb.CreateMissionRequest) (*componentpb.CreateMissionResponse, error) {
	tenant, grantID, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}

	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil || id.Subject == "" {
		return nil, status.Error(codes.Unauthenticated, "caller identity unavailable")
	}

	// The parent is whatever mission the caller's CURRENT work item belongs
	// to. A work id the caller does not own resolves to "" here, not to
	// someone else's mission, and origination is then refused for want of a
	// parent — the same answer a caller with no work item at all gets.
	parentMissionID, _, resolveErr := resolveMissionContext(ctx, s.missionCtx, req.GetWorkId(), tenant, "", s.logger)
	if resolveErr != nil {
		s.logger.ErrorContext(ctx, "CreateMission: failed to resolve the caller's work context",
			"tenant", tenant, "work_id", req.GetWorkId(), "error", resolveErr)
		return nil, status.Error(codes.Internal, "failed to resolve the calling work context")
	}

	missionJSON, err := s.missionMgr.OriginateMission(ctx, OriginateMissionRequest{
		ParentMissionID: parentMissionID,
		ParentWorkID:    req.GetWorkId(),
		Principal:       id.Subject,
		GrantID:         grantID,
		DefinitionJSON:  req.GetMissionDefinitionJson(),
		TargetID:        req.GetTargetId(),
		OptsJSON:        req.GetOptsJson(),
	})
	if err != nil {
		s.logger.WarnContext(ctx, "CreateMission refused", "tenant", tenant, "error", err)
		return nil, missionError(err, "create failed")
	}
	return &componentpb.CreateMissionResponse{MissionJson: missionJSON}, nil
}

// RunMission queues a mission for execution.
func (s *ComponentServiceServer) RunMission(ctx context.Context, req *componentpb.RunMissionRequest) (*componentpb.RunMissionResponse, error) {
	tenant, _, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.missionMgr.RunMission(ctx, tenant, req.GetMissionId(), req.GetOptsJson()); err != nil {
		s.logger.Error("RunMission failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, missionError(err, "run failed")
	}
	return &componentpb.RunMissionResponse{}, nil
}

// GetMissionStatus returns the current status of a mission.
func (s *ComponentServiceServer) GetMissionStatus(ctx context.Context, req *componentpb.GetMissionStatusRequest) (*componentpb.GetMissionStatusResponse, error) {
	tenant, _, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}
	statusJSON, err := s.missionMgr.GetMissionStatus(ctx, tenant, req.GetMissionId())
	if err != nil {
		s.logger.Error("GetMissionStatus failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, missionError(err, "status query failed")
	}
	return &componentpb.GetMissionStatusResponse{StatusJson: statusJSON}, nil
}

// WaitMission blocks until a mission completes or the timeout expires.
//
// Disconnect behaviour (the question gibson#1186 slice C left open): the
// caller dropping does NOT cancel the mission. The RPC's context is
// cancelled, the daemon's poll loop returns, and the mission keeps running —
// waiting is an observation, not a lease. A component that wants the mission
// stopped calls CancelMission, which says so explicitly.
func (s *ComponentServiceServer) WaitMission(ctx context.Context, req *componentpb.WaitMissionRequest) (*componentpb.WaitMissionResponse, error) {
	tenant, _, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}
	resultJSON, err := s.missionMgr.WaitForMission(ctx, tenant, req.GetMissionId(), req.GetTimeoutMs())
	if err != nil {
		s.logger.Error("WaitMission failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, missionError(err, "wait failed")
	}
	return &componentpb.WaitMissionResponse{ResultJson: resultJSON}, nil
}

// ListMissions returns missions matching the given filter.
func (s *ComponentServiceServer) ListMissions(ctx context.Context, req *componentpb.ListMissionsRequest) (*componentpb.ListMissionsResponse, error) {
	tenant, _, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}
	missionsJSON, err := s.missionMgr.ListMissions(ctx, tenant, req.GetFilterJson())
	if err != nil {
		s.logger.Error("ListMissions failed", "tenant", tenant, "error", err)
		return nil, missionError(err, "list failed")
	}
	return &componentpb.ListMissionsResponse{MissionsJson: missionsJSON}, nil
}

// CancelMission requests cancellation of a running mission.
func (s *ComponentServiceServer) CancelMission(ctx context.Context, req *componentpb.CancelMissionRequest) (*componentpb.CancelMissionResponse, error) {
	tenant, _, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.missionMgr.CancelMission(ctx, tenant, req.GetMissionId()); err != nil {
		s.logger.Error("CancelMission failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, missionError(err, "cancel failed")
	}
	return &componentpb.CancelMissionResponse{}, nil
}

// GetMissionResults returns the final results of a completed mission.
func (s *ComponentServiceServer) GetMissionResults(ctx context.Context, req *componentpb.GetMissionResultsRequest) (*componentpb.GetMissionResultsResponse, error) {
	tenant, _, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}
	resultsJSON, err := s.missionMgr.GetMissionResults(ctx, tenant, req.GetMissionId())
	if err != nil {
		s.logger.Error("GetMissionResults failed", "tenant", tenant, "mission_id", req.GetMissionId(), "error", err)
		return nil, missionError(err, "results query failed")
	}
	return &componentpb.GetMissionResultsResponse{ResultJson: resultsJSON}, nil
}

// GetMissionRunHistory returns the run history for the mission behind a work
// item.
func (s *ComponentServiceServer) GetMissionRunHistory(ctx context.Context, req *componentpb.GetMissionRunHistoryRequest) (*componentpb.GetMissionRunHistoryResponse, error) {
	tenant, _, err := s.missionCall(ctx)
	if err != nil {
		return nil, err
	}
	// Same resolution as CreateMission's parent lookup, and the same refusal:
	// a work id belonging to another tenant resolves to "", so the answer is
	// "no such history", never someone else's.
	missionID, _, resolveErr := resolveMissionContext(ctx, s.missionCtx, req.GetWorkId(), tenant, "", s.logger)
	if resolveErr != nil {
		s.logger.ErrorContext(ctx, "GetMissionRunHistory: failed to resolve the caller's work context",
			"tenant", tenant, "work_id", req.GetWorkId(), "error", resolveErr)
		return nil, status.Error(codes.Internal, "failed to resolve the calling work context")
	}
	if missionID == "" {
		return nil, status.Errorf(codes.NotFound, "no mission is associated with work item %q", req.GetWorkId())
	}

	runsJSON, err := s.missionMgr.GetMissionRunHistory(ctx, tenant, missionID)
	if err != nil {
		s.logger.Error("GetMissionRunHistory failed", "tenant", tenant, "error", err)
		return nil, missionError(err, "history query failed")
	}
	return &componentpb.GetMissionRunHistoryResponse{RunsJson: runsJSON}, nil
}
