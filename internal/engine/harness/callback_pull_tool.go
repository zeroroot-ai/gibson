// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"google.golang.org/protobuf/proto"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// CallPullTool runs a sandboxed catalog tool for an agent in pull mode, which
// reaches the daemon through ComponentService.CallTool. The call runs through
// callTool, the one path of a tool call from an agent. So it takes the harness
// that the daemon registered for the node of the agent, with the network scope
// of that node, and the same deny list, events and flight recorder record as
// the call of an agent in callback mode.
//
// Beyond that path, a pull call checks what a callback has already settled: the
// run belongs to the tenant, the mission policy loads, and the run is still
// active. A server with no flight recorder refuses the call, because a call
// that the daemon starts must leave its record. A node whose harness is not
// registered refuses the call too, so the scope of a node is never guessed.
func (s *HarnessCallbackService) CallPullTool(
	ctx context.Context, tenant, missionID, runID, agent, task, name string, input []byte,
) (*harnesspb.CallToolProtoResponse, error) {
	refuse := func(code commonpb.ErrorCode, msg string) (*harnesspb.CallToolProtoResponse, error) {
		// gibson:no-tool-executed — refused before any dispatch is attempted.
		return &harnesspb.CallToolProtoResponse{Error: &harnesspb.HarnessError{Code: code, Message: msg}}, nil
	}
	if runID == "" || agent == "" {
		return refuse(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "a sandboxed tool call needs the work item of an agent run")
	}
	if s.toolCallSink == nil {
		return refuse(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "this daemon has no flight recorder, so it refuses a sandboxed tool call")
	}
	if s.authzStore == nil {
		return refuse(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the run authorization store is not wired")
	}
	state, err := s.authzStore.Get(ctx, runID)
	if err != nil || state.TenantID != tenant {
		return refuse(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "run authz state not found")
	}
	policy, err := s.policyFromState(ctx, state)
	if err != nil {
		s.logger.ErrorContext(ctx, "pull tool call refused: the mission policy could not be loaded", "run_id", runID, "err", err)
		return refuse(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the mission policy could not be loaded")
	}
	if err := policy.CheckRun(ctx); err != nil {
		return refuse(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "mission run is not active")
	}
	response := &componentpb.CallToolResponse{}
	messages := func(_ context.Context, _ AgentHarness, req *harnesspb.CallToolProtoRequest) (proto.Message, proto.Message, *harnesspb.CallToolProtoResponse) {
		return &componentpb.CallToolRequest{ToolName: req.Name, InputJson: string(req.InputJson)}, response, nil
	}
	out, err := s.callTool(ctx, &harnesspb.CallToolProtoRequest{
		Context:   &harnesspb.ContextInfo{MissionId: missionID, MissionRunId: runID, AgentName: agent, TaskId: task},
		Name:      name,
		InputJson: input,
	}, messages)
	if err != nil || out.GetError() != nil {
		return out, err
	}
	// The result of the tool is the output_json of its response message, not
	// the JSON of the message.
	out.OutputJson = []byte(response.GetOutputJson())
	if e := response.GetError(); e != nil {
		out.Error = &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Message: e.GetMessage()}
	}
	return out, nil
}
