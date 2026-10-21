// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// MissionPolicySource returns the mission policy of a run: its deny list and
// whether it may call tools.
type MissionPolicySource func(ctx context.Context, runID string) (metatool.MissionPolicy, error)

// WithConnectorCaller wires the one MCP client of the daemon as the caller of
// connector tools. ListTools returns the id mcp:<connector>:<tool> for each
// connector tool, and CallTool takes that id back (ADR-0065).
func (s *ComponentServiceServer) WithConnectorCaller(c metatool.ConnectorCaller) *ComponentServiceServer {
	s.connectorCaller = c
	return s
}

// WithMissionPolicy wires the source of the mission policy of a run. A
// connector call that names a work item takes the policy of its run.
func (s *ComponentServiceServer) WithMissionPolicy(src MissionPolicySource) *ComponentServiceServer {
	s.missionPolicy = src
	return s
}

// connectorToolID returns the id of a connector tool when name is one.
func connectorToolID(name string) (toolid.ID, bool) {
	tid, err := toolid.Parse(name)
	if err != nil || tid.Source != toolid.SourceMCP {
		return toolid.ID{}, false
	}
	return tid, true
}

// callConnectorTool serves CallTool for an mcp:<connector>:<tool> id. The call
// itself is the one function that invoke_tool also uses, metatool.Handler.Call:
// the mission policy, the can_execute check on the connector, the intent
// record, the dispatch, and the result record. This function adds what only
// this path has: the claim check of the work id that the caller names.
func (s *ComponentServiceServer) callConnectorTool(
	ctx context.Context,
	tenant string,
	req *componentpb.CallToolRequest,
	tid toolid.ID,
) (*componentpb.CallToolResponse, error) {
	if s.connectorCaller == nil || s.authorizer == nil {
		return nil, status.Error(codes.Unimplemented, "connector tool calls are not configured")
	}
	if s.auditLog == nil {
		return nil, status.Error(codes.FailedPrecondition, "the audit log is not wired on this server")
	}
	caller, err := s.catalogCaller(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(req.InputJson), &args); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "input_json must be a JSON object: %v", err)
	}

	call := metatool.Call{
		Caller:   caller,
		ID:       tid.Canonical(),
		Args:     args,
		ArgsJSON: []byte(req.InputJson),
		Observer: connectorAuditObserver{s: s},
	}
	// A work id names a mission. The caller must have claimed the work item
	// before the id selects a mission or a run, or an agent could name the work
	// of another mission.
	if req.WorkId != "" {
		if _, err := s.resolveClaimedWork(ctx, tenant, req.WorkId); err != nil {
			return nil, err
		}
		call.WorkID = req.WorkId
		missionID, mErr := resolveMissionContext(ctx, s.missionCtx, req.WorkId, tenant)
		if mErr != nil {
			s.logger.WarnContext(ctx, "call tool: mission lookup failed", slog.String("work_id", req.WorkId), slog.String("error", mErr.Error()))
		}
		call.MissionID = missionID
		policy, pErr := s.policyOfWork(ctx, req.WorkId)
		if pErr != nil {
			return nil, pErr
		}
		call.Policy = policy
	}

	result, err := metatool.NewHandler(nil, catalog.NewFGAAuthorizer(s.authorizer), s.connectorCaller).Call(ctx, call)
	switch {
	case err == nil:
		out, mErr := json.Marshal(result)
		if mErr != nil {
			return nil, status.Errorf(codes.Internal, "encode the connector result: %v", mErr)
		}
		return &componentpb.CallToolResponse{OutputJson: string(out)}, nil
	case errors.Is(err, metatool.ErrBlocked), errors.Is(err, metatool.ErrRunInactive), errors.Is(err, metatool.ErrUnauthorized):
		return nil, status.Errorf(codes.PermissionDenied, "the call of %s is not allowed", tid.Canonical())
	case errors.Is(err, metatool.ErrAuditUnavailable):
		s.logger.ErrorContext(ctx, "call tool: refused, the audit record could not be written", slog.String("error", err.Error()))
		return nil, status.Error(codes.Unavailable, "the audit record of the call could not be written")
	default:
		s.logger.WarnContext(ctx, "call tool: connector call failed",
			slog.String("tenant", tenant), slog.String("tool", tid.Canonical()), slog.String("error", err.Error()))
		return &componentpb.CallToolResponse{Error: &componentpb.ComponentError{
			Code: "[CONNECTOR_CALL_FAILED]", Message: err.Error(),
		}}, nil
	}
}

// policyOfWork returns the mission policy of the run of a work item. A work
// item with no run has no mission policy. A server that cannot read the policy
// of a run refuses the call: an unread policy is not an empty one.
func (s *ComponentServiceServer) policyOfWork(ctx context.Context, workID string) (metatool.MissionPolicy, error) {
	run, err := s.workContext.WorkRun(ctx, workID)
	if err != nil {
		if errors.Is(err, ErrWorkRunUnknown) {
			return metatool.MissionPolicy{}, nil
		}
		return metatool.MissionPolicy{}, status.Errorf(codes.Internal, "failed to resolve the run of work %q", workID)
	}
	if s.missionPolicy == nil {
		return metatool.MissionPolicy{}, status.Error(codes.FailedPrecondition, "the mission policy source is not configured")
	}
	policy, err := s.missionPolicy(ctx, run)
	if err != nil {
		s.logger.ErrorContext(ctx, "call tool: the mission policy of the run could not be read",
			slog.String("run_id", run), slog.String("error", err.Error()))
		return metatool.MissionPolicy{}, status.Error(codes.Unavailable, "the mission policy of the run could not be read")
	}
	return policy, nil
}

// connectorAuditObserver writes the audit records of a connector call made
// through CallTool. The actor is the identity of the caller: for an enrolled
// agent, its agent principal with the actor source agent.
type connectorAuditObserver struct{ s *ComponentServiceServer }

var _ metatool.CallObserver = connectorAuditObserver{}

func (o connectorAuditObserver) Intent(ctx context.Context, rec metatool.CallRecord) error {
	return metatool.AuditRecorder{Log: o.s.auditLog}.Intent(ctx, rec)
}

func (o connectorAuditObserver) Result(ctx context.Context, rec metatool.CallRecord, _ []byte, callErr error) {
	if rec.Connector == "" {
		return
	}
	if err := (metatool.AuditRecorder{Log: o.s.auditLog}).Result(ctx, rec, callErr); err != nil {
		o.s.logger.ErrorContext(ctx, "call tool: the result audit record of a connector call was not written",
			slog.String("tenant", rec.Tenant), slog.String("connector", rec.Connector), slog.String("error", err.Error()))
	}
}
