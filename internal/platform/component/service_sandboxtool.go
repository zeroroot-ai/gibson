// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// SandboxToolReply is the answer of a sandboxed catalog tool.
type SandboxToolReply struct {
	// OutputJSON is the result. Empty when the call failed.
	OutputJSON string
	// ErrorCode and ErrorMessage describe a failed call. Both are empty on success.
	ErrorCode    string
	ErrorMessage string
}

// SandboxToolCaller runs a sandboxed catalog tool for an agent in pull mode. The
// daemon implements it with the harness of the run, so the call takes the same
// gates and the same sandbox launch as the call of an agent in callback mode.
type SandboxToolCaller interface {
	CallSandboxedTool(ctx context.Context, tenant, missionID, runID, name string, input []byte) (SandboxToolReply, error)
}

// WithSandboxTools wires the caller of sandboxed catalog tools. A server with
// none refuses such a call.
func (s *ComponentServiceServer) WithSandboxTools(c SandboxToolCaller) *ComponentServiceServer {
	s.sandboxTools = c
	return s
}

// isSandboxedCatalogTool reports whether the catalog holds name as a tool that
// runs in a sandbox. The daemon launches that tool. It has no work queue.
func isSandboxedCatalogTool(name string) bool {
	entry, ok := componentcatalog.LookupTool(name)
	return ok && entry.DispatchMode == componentcatalog.DispatchModeSandboxed
}

// callSandboxedTool serves a sandboxed catalog tool on CallTool. The work id
// that the caller names must be claimed by the caller, and it selects the
// mission and the run. A call with no mission run is refused, because the
// sandbox launch belongs to a run. The record of the call is the flight
// recorder record of a native tool call, and the reply carries its id.
func (s *ComponentServiceServer) callSandboxedTool(
	ctx context.Context, tenant string, req *componentpb.CallToolRequest,
) (*componentpb.CallToolResponse, error) {
	if s.sandboxTools == nil {
		return nil, status.Error(codes.Unimplemented, "sandboxed tools are not configured on this server")
	}
	var bound metatool.Call
	if err := s.bindCallRun(ctx, tenant, req, &bound); err != nil {
		return nil, err
	}
	if bound.RunID == "" || bound.MissionID == "" {
		return nil, status.Error(codes.FailedPrecondition, "a sandboxed tool call needs the work item of a mission run")
	}
	reply, err := s.sandboxTools.CallSandboxedTool(ctx, tenant, bound.MissionID, bound.RunID, req.GetToolName(), []byte(req.GetInputJson()))
	if err != nil {
		s.logger.WarnContext(ctx, "call tool: sandboxed tool failed",
			slog.String("tool", req.GetToolName()), slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Internal, "sandboxed tool %s failed", req.GetToolName())
	}
	out := &componentpb.CallToolResponse{OutputJson: reply.OutputJSON}
	errText := ""
	if reply.ErrorCode != "" || reply.ErrorMessage != "" {
		out.Error = &componentpb.ComponentError{Code: "[" + reply.ErrorCode + "]", Message: reply.ErrorMessage}
		errText = reply.ErrorMessage
	}
	out.ToolCallId = s.recordNativeToolCall(ctx, tenant, req, reply.OutputJSON, errText)
	return out, nil
}
