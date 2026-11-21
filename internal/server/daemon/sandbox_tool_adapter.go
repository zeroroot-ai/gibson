// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// sandboxToolAdapter runs a sandboxed catalog tool for an agent in pull mode. It
// builds the harness of the run with the factory of the daemon and calls the
// same CallToolProto that an agent in callback mode reaches. So the execute
// gate, the files of an Agent Skill and the sandbox launch have one code path.
type sandboxToolAdapter struct{ d *daemonImpl }

var _ component.SandboxToolCaller = sandboxToolAdapter{}

// CallSandboxedTool runs the tool. A refusal or a failure of the call is a reply
// with an error, so the agent reads why. A daemon with no harness factory, and a
// mission id that is not an id, are errors of the call itself.
func (a sandboxToolAdapter) CallSandboxedTool(
	ctx context.Context, tenant, missionID, runID, name string, input []byte,
) (component.SandboxToolReply, error) {
	if a.d.infrastructure == nil || a.d.infrastructure.harnessFactory == nil {
		return component.SandboxToolReply{}, errors.New("the daemon has no harness factory")
	}
	mid, err := types.ParseID(missionID)
	if err != nil {
		return component.SandboxToolReply{}, fmt.Errorf("mission id %q: %w", missionID, err)
	}
	agent := callerAgentName(ctx)
	h, err := a.d.infrastructure.harnessFactory.Create(agent, harness.MissionContext{
		ID: mid, TenantID: tenant, MissionRunID: runID, AgentRunID: runID,
	}, harness.TargetInfo{})
	if err != nil {
		return component.SandboxToolReply{}, fmt.Errorf("create the harness of run %q: %w", runID, err)
	}
	req := &componentpb.CallToolRequest{ToolName: name, InputJson: string(input)}
	resp := &componentpb.CallToolResponse{}
	if err := h.CallToolProto(ctx, name, req, resp); err != nil {
		code := "TOOL_FAILED"
		var ge *types.GibsonError
		if errors.As(err, &ge) {
			code = string(ge.Code)
		}
		return component.SandboxToolReply{ErrorCode: code, ErrorMessage: err.Error()}, nil
	}
	reply := component.SandboxToolReply{OutputJSON: resp.GetOutputJson()}
	if e := resp.GetError(); e != nil {
		reply.ErrorCode, reply.ErrorMessage = e.GetCode(), e.GetMessage()
	}
	return reply, nil
}

// callerAgentName is the name of the agent that makes the call: the name of its
// principal when the identity is an agent principal, else "agent". The name only
// selects the egress ceiling that the catalog states for an agent of that name.
func callerAgentName(ctx context.Context) string {
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		if name, ok := strings.CutPrefix(id.Subject, "agent_principal:"); ok && name != "" {
			return name
		}
	}
	return "agent"
}
