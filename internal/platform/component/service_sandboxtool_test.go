// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// fakeSandboxTools records each call and answers with a fixed reply.
type fakeSandboxTools struct {
	calls []string
	input []byte
	reply SandboxToolReply
	err   error
}

func (f *fakeSandboxTools) CallSandboxedTool(_ context.Context, tenant, mission, run, name string, input []byte) (SandboxToolReply, error) {
	f.calls = append(f.calls, tenant+"|"+mission+"|"+run+"|"+name)
	f.input = input
	return f.reply, f.err
}

func scriptReq(workID string) *componentpb.CallToolRequest {
	return &componentpb.CallToolRequest{ToolName: "skill-script", InputJson: `{"target":"web-recon/scripts/probe.sh"}`, WorkId: workID}
}

// An agent in pull mode runs a sandboxed catalog tool by its own name. The
// call reaches the caller with the mission and the run of the claimed work
// item, and the flight recorder holds it as a native tool call.
func TestCallTool_ASandboxedCatalogToolReachesTheSandboxCaller(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	fake := &fakeSandboxTools{reply: SandboxToolReply{OutputJSON: `{"exit_code":0}`}}
	env.srv.WithSandboxTools(fake)

	resp, err := env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-9"))
	require.NoError(t, err)
	assert.Equal(t, []string{"test-tenant|mission-7|run-1|skill-script"}, fake.calls)
	assert.JSONEq(t, `{"target":"web-recon/scripts/probe.sh"}`, string(fake.input))
	assert.JSONEq(t, `{"exit_code":0}`, resp.GetOutputJson())
	assert.Nil(t, resp.GetError())
	assert.Equal(t, "call-1", resp.GetToolCallId(), "the reply must carry the id of the flight recorder record")
	require.Len(t, env.recorded, 1)
	assert.Equal(t, "native:skill-script", env.recorded[0].Canonical)
	assert.Equal(t, "mission-7", env.recorded[0].MissionID)
	assert.Equal(t, "run-1", env.recorded[0].RunID)
}

// A refusal of the call is a reply with an error, so the agent reads why, and
// the record holds the refusal.
func TestCallTool_ASandboxedToolRefusalIsAReplyWithAnError(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	env.srv.WithSandboxTools(&fakeSandboxTools{reply: SandboxToolReply{ErrorCode: "SANDBOX_POLICY_DENIED", ErrorMessage: "the caller may not load the Agent Skill"}})

	resp, err := env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-9"))
	require.NoError(t, err)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, "[SANDBOX_POLICY_DENIED]", resp.GetError().GetCode())
	assert.Contains(t, resp.GetError().GetMessage(), "may not load")
	assert.Empty(t, resp.GetOutputJson())
	assert.Equal(t, "call-1", resp.GetToolCallId(), "a refused call is recorded too")
}

func TestCallTool_ASandboxedToolNeedsARunAndACaller(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")

	// No caller wired.
	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-9"))
	assert.Equal(t, codes.Unimplemented, status.Code(err))

	fake := &fakeSandboxTools{}
	env.srv.WithSandboxTools(fake)
	// No work item, so no mission run.
	_, err = env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq(""))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	// A work item that another caller claimed.
	_, err = env.srv.CallTool(agentCtx("agent_principal:43"), scriptReq("work-9"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, fake.calls, "no refused call reached the sandbox caller")

	// A failure of the caller itself.
	fake.err = errors.New("no harness factory")
	_, err = env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-9"))
	assert.Equal(t, codes.Internal, status.Code(err))
}
