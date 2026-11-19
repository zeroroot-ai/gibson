// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// MetaToolReply is the answer of a meta-tool call.
type MetaToolReply struct {
	// OutputJSON is the result. Empty when the call failed.
	OutputJSON string
	// ErrorCode and ErrorMessage describe a failed call. Both are empty on success.
	ErrorCode    string
	ErrorMessage string
	// ToolCallID is the id of the recorded call of the invoked tool.
	ToolCallID string
}

// MetaToolCaller serves search_tools and invoke_tool for an agent in pull mode.
// The callback service implements it, so both paths share one handler.
type MetaToolCaller interface {
	CallMetaTool(ctx context.Context, tenant, missionID, runID, name string, input []byte) (MetaToolReply, error)
}

// WithMetaTools wires the meta-tool server. A server with none refuses a
// meta-tool call.
func (s *ComponentServiceServer) WithMetaTools(c MetaToolCaller) *ComponentServiceServer {
	s.metaTools = c
	return s
}

// callMetaTool serves search_tools and invoke_tool on CallTool. The SDK loads
// the pinned Agent Skills of a run through invoke_tool. The work id that the
// caller names must be claimed by the caller, and it selects the mission and
// the run.
func (s *ComponentServiceServer) callMetaTool(
	ctx context.Context, tenant string, req *componentpb.CallToolRequest,
) (*componentpb.CallToolResponse, error) {
	if s.metaTools == nil {
		return nil, status.Error(codes.Unimplemented, "meta-tools are not configured on this server")
	}
	var bound metatool.Call
	if err := s.bindCallRun(ctx, tenant, req, &bound); err != nil {
		return nil, err
	}
	reply, err := s.metaTools.CallMetaTool(ctx, tenant, bound.MissionID, bound.RunID, req.GetToolName(), []byte(req.GetInputJson()))
	if err != nil {
		s.logger.WarnContext(ctx, "call tool: meta-tool failed", slog.String("tool", req.GetToolName()), slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Internal, "meta-tool %s failed", req.GetToolName())
	}
	out := &componentpb.CallToolResponse{OutputJson: reply.OutputJSON, ToolCallId: reply.ToolCallID}
	if reply.ErrorCode != "" || reply.ErrorMessage != "" {
		out.Error = &componentpb.ComponentError{Code: "[" + reply.ErrorCode + "]", Message: reply.ErrorMessage}
	}
	return out, nil
}

// recordNativeToolCall writes the flight recorder record of a tool call that went
// through the work queue, and returns the id of the record. The record has the
// mission and the run of the work item, so a finding that cites the id gets tier 1
// evidence. It returns an empty string when the server has no recorder, or when
// the work item names no run.
func (s *ComponentServiceServer) recordNativeToolCall(
	ctx context.Context, tenant string, req *componentpb.CallToolRequest, resultJSON, errText string,
) string {
	if s.toolCallRecorder == nil {
		return ""
	}
	var bound metatool.Call
	if err := s.bindCallRun(ctx, tenant, req, &bound); err != nil || bound.RunID == "" {
		return ""
	}
	return s.toolCallRecorder(ctx, metatool.CallRecord{
		Tenant: tenant, Canonical: "native:" + req.GetToolName(), Tool: req.GetToolName(),
		ArgsJSON: []byte(req.GetInputJson()), WorkID: bound.WorkID, MissionID: bound.MissionID, RunID: bound.RunID,
	}, []byte(resultJSON), errText)
}
