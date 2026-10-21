// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// MissionPolicySource returns the mission policy of a run of the tenant: the
// deny list of its stored mission and whether the run may call tools.
type MissionPolicySource func(ctx context.Context, tenant, runID string) (metatool.MissionPolicy, error)

// WithConnectorCaller wires the one MCP client of the daemon as the caller of
// connector tools. ListTools returns the id mcp:<connector>:<tool> for each
// connector tool, and CallTool takes that id back (ADR-0065).
func (s *ComponentServiceServer) WithConnectorCaller(c metatool.ConnectorCaller) *ComponentServiceServer {
	s.connectorCaller = c
	return s
}

// WithToolCallRecorder wires the flight recorder of connector calls. A server
// with none refuses a connector call (ADR-0131).
func (s *ComponentServiceServer) WithToolCallRecorder(r metatool.FlightRecorder) *ComponentServiceServer {
	s.toolCallRecorder = r
	return s
}

// WithMissionPolicy wires the source of the mission policy of a run. A
// connector call that belongs to a run takes the policy of that run.
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
	if s.toolCallRecorder == nil {
		return nil, status.Error(codes.FailedPrecondition, "the flight recorder is not wired on this server")
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
		Recorder: s.toolCallRecorder,
		Observer: connectorAuditObserver{s: s},
	}
	if err := s.bindCallRun(ctx, tenant, req, &call); err != nil {
		return nil, err
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

// bindCallRun sets the work item, the mission, the run and the mission policy of
// a call. A work id names a mission run, and so does a task grant. The caller
// must have claimed the work item before its id selects a mission or a run, or
// an agent could name the work of another mission. A call with no run keeps the
// can_execute check only. A call with a run takes the policy of that run, and a
// policy that cannot be read refuses it.
func (s *ComponentServiceServer) bindCallRun(ctx context.Context, tenant string, req *componentpb.CallToolRequest, call *metatool.Call) error {
	var workRun string
	if req.WorkId != "" {
		if _, err := s.resolveClaimedWork(ctx, tenant, req.WorkId); err != nil {
			return err
		}
		call.WorkID = req.WorkId
		missionID, mErr := resolveMissionContext(ctx, s.missionCtx, req.WorkId, tenant)
		if mErr != nil {
			s.logger.WarnContext(ctx, "call tool: mission lookup failed", slog.String("work_id", req.WorkId), slog.String("error", mErr.Error()))
		}
		call.MissionID = missionID
		run, rErr := s.workContext.WorkRun(ctx, req.WorkId)
		if rErr != nil && !errors.Is(rErr, ErrWorkRunUnknown) {
			return status.Errorf(codes.Internal, "failed to resolve the run of work %q", req.WorkId)
		}
		workRun = run
	}
	grantRun, gErr := s.optionalGrantRun(ctx, tenant)
	if gErr != nil {
		return gErr
	}
	if workRun != "" && grantRun != "" && workRun != grantRun {
		return status.Error(codes.PermissionDenied, "the work item belongs to another run than the grant")
	}
	call.RunID = workRun
	if call.RunID == "" {
		call.RunID = grantRun
	}
	if call.RunID == "" {
		return nil
	}
	policy, pErr := s.policyOfRun(ctx, tenant, call.RunID)
	if pErr != nil {
		return pErr
	}
	call.Policy = policy
	return nil
}

// policyOfRun returns the mission policy of a run. A server that cannot read
// the policy refuses the call: an unread policy is not an empty one.
func (s *ComponentServiceServer) policyOfRun(ctx context.Context, tenant, runID string) (metatool.MissionPolicy, error) {
	if s.missionPolicy == nil {
		return metatool.MissionPolicy{}, status.Error(codes.FailedPrecondition, "the mission policy source is not configured")
	}
	policy, err := s.missionPolicy(ctx, tenant, runID)
	if err != nil {
		s.logger.ErrorContext(ctx, "call tool: the mission policy of the run could not be read",
			slog.String("run_id", runID), slog.String("error", err.Error()))
		return metatool.MissionPolicy{}, status.Error(codes.Unavailable, "the mission policy of the run could not be read")
	}
	return policy, nil
}

// optionalGrantRun returns the mission run that the verified task grant of the
// caller names. A caller with no task grant, such as an enrolled agent on its
// host key, has no run and gets an empty answer. A task grant that does not
// verify refuses the call.
func (s *ComponentServiceServer) optionalGrantRun(ctx context.Context, tenant string) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-capability-grant")
	switch len(values) {
	case 0:
		return "", nil
	case 1:
		token := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(values[0], "Bearer "), "bearer "))
		parts := strings.Split(token, ".")
		if len(parts) != 3 || tokenHeaderType(parts[0]) != "JWT" {
			return "", nil // a component grant names no run
		}
	}
	_, run, err := s.callerTaskGrant(ctx, tenant)
	return run, err
}

// connectorAuditObserver writes the audit records of a connector call made
// through CallTool. The actor is the identity of the caller: for an enrolled
// agent, its agent principal with the actor source agent.
type connectorAuditObserver struct{ s *ComponentServiceServer }

var _ metatool.CallObserver = connectorAuditObserver{}

func (o connectorAuditObserver) Intent(ctx context.Context, rec metatool.CallRecord) error {
	if err := (metatool.AuditRecorder{Log: o.s.auditLog}).Intent(ctx, rec); err != nil {
		return fmt.Errorf("audit intent of %s: %w", rec.Canonical, err)
	}
	return nil
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
