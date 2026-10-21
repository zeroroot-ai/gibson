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

// Audit names of a connector tool call. The action is the one name that a
// reader of the audit trail filters on. The resource is the connector.
const (
	connectorCallAction   = "connector.tool.call"
	connectorCallResource = "connector"
)

// WithConnectorCaller wires the one MCP client of the daemon as the caller of
// connector tools. ListTools returns the id mcp:<connector>:<tool> for each
// connector tool, and CallTool takes that id back (ADR-0065).
func (s *ComponentServiceServer) WithConnectorCaller(c metatool.ConnectorCaller) *ComponentServiceServer {
	s.connectorCaller = c
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

// callConnectorTool serves CallTool for an mcp:<connector>:<tool> id. It runs
// the same checks and the same MCP client as the invoke_tool meta-tool: the
// can_execute check on the connector, then one call of the daemon to the
// connector. It writes one audit record for the call, whatever its result.
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

	handler := metatool.NewHandler(nil, catalog.NewFGAAuthorizer(s.authorizer), s.connectorCaller)
	if _, err := handler.Authorize(ctx, caller, tid.Canonical()); err != nil {
		s.auditConnectorCall(ctx, tenant, req, tid, err)
		if errors.Is(err, metatool.ErrUnauthorized) {
			return nil, status.Errorf(codes.PermissionDenied, "not authorized to call %s", tid.Canonical())
		}
		return nil, status.Errorf(codes.Internal, "authorization check failed for %s", tid.Canonical())
	}

	result, err := handler.Dispatch(ctx, caller, tid, args)
	s.auditConnectorCall(ctx, tenant, req, tid, err)
	if err != nil {
		s.logger.WarnContext(ctx, "call tool: connector call failed",
			slog.String("tenant", tenant), slog.String("tool", tid.Canonical()), slog.String("error", err.Error()))
		return &componentpb.CallToolResponse{Error: &componentpb.ComponentError{
			Code: "[CONNECTOR_CALL_FAILED]", Message: err.Error(),
		}}, nil
	}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode the connector result: %v", err)
	}
	return &componentpb.CallToolResponse{OutputJson: string(out)}, nil
}

// auditConnectorCall writes the audit record of one connector tool call. The
// actor is the identity on the context: for an enrolled agent, its agent
// principal with the actor source "agent". The target is the connector. A call
// that carries a work id also names the mission of that work, under mission_id.
// A failed write is logged and never changes the result of the call, which has
// already happened.
func (s *ComponentServiceServer) auditConnectorCall(
	ctx context.Context,
	tenant string,
	req *componentpb.CallToolRequest,
	tid toolid.ID,
	callErr error,
) {
	details := map[string]any{"tool": tid.Tool}
	if req.WorkId != "" {
		details["work_id"] = req.WorkId
		missionID, err := resolveMissionContext(ctx, s.missionCtx, req.WorkId, tenant)
		if err != nil {
			s.logger.WarnContext(ctx, "call tool: mission lookup for the audit record failed",
				slog.String("work_id", req.WorkId), slog.String("error", err.Error()))
		}
		if missionID != "" {
			details["mission_id"] = missionID
		}
	}
	result := "success"
	if callErr != nil {
		result = "failure"
		details["error"] = connectorCallErrorClass(callErr)
	}
	if _, err := s.auditLog.RecordWithResult(ctx, connectorCallAction, connectorCallResource, tid.Connector, result, details); err != nil {
		s.logger.ErrorContext(ctx, "call tool: the audit record of a connector call was not written",
			slog.String("tenant", tenant), slog.String("connector", tid.Connector), slog.String("error", err.Error()))
	}
}

// connectorCallErrorClass names why a call failed without the text of the
// error, which can hold what the connector returned.
func connectorCallErrorClass(err error) string {
	switch {
	case errors.Is(err, metatool.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrUnknownConnector):
		return "unknown_connector"
	default:
		return "failed"
	}
}
