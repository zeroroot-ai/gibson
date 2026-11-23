// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// sandboxToolAdapter serves the sandboxed catalog tools of ComponentService with
// the call path of the callback service, so an agent in pull mode and an agent
// in callback mode share one implementation of the gates, the network scope and
// the flight recorder record.
type sandboxToolAdapter struct{ svc pullToolCaller }

// pullToolCaller is the part of the callback manager that the adapter uses.
type pullToolCaller interface {
	CallPullTool(ctx context.Context, tenant, missionID, runID, agent, task, name string, input []byte) (*harnesspb.CallToolProtoResponse, error)
}

var _ component.SandboxToolCaller = sandboxToolAdapter{}

// CallSandboxedTool maps the reply of the callback path to a SandboxToolReply.
func (a sandboxToolAdapter) CallSandboxedTool(
	ctx context.Context, tenant, missionID, runID, agent, task, name string, input []byte,
) (component.SandboxToolReply, error) {
	resp, err := a.svc.CallPullTool(ctx, tenant, missionID, runID, agent, task, name, input)
	if err != nil {
		return component.SandboxToolReply{}, fmt.Errorf("sandboxed tool %s: %w", name, err)
	}
	out := component.SandboxToolReply{OutputJSON: string(resp.GetOutputJson()), ToolCallID: resp.GetToolCallId()}
	if e := resp.GetError(); e != nil {
		out.ErrorCode, out.ErrorMessage = e.GetCode().String(), e.GetMessage()
	}
	return out, nil
}
