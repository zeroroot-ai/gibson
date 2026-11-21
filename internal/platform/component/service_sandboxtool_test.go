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

func (f *fakeSandboxTools) CallSandboxedTool(_ context.Context, tenant, mission, run, agent, task, name string, input []byte) (SandboxToolReply, error) {
	f.calls = append(f.calls, tenant+"|"+mission+"|"+run+"|"+agent+"|"+task+"|"+name)
	f.input = input
	return f.reply, f.err
}

// bindAgent records the agent and the task of a work item, as Enqueue does for
// agent work.
func (e *connectorEnv) bindAgent(t *testing.T, workID, agent, task string) {
	t.Helper()
	item := WorkItem{WorkID: workID, Context: map[string]string{WorkTaskContextKey: task}}
	require.NoError(t, bindWorkAgent(context.Background(), e.reg.stateClient.Client(), "agent", agent, item))
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
	env.bindAgent(t, "work-9", "scan-agent", "task-3")
	fake := &fakeSandboxTools{reply: SandboxToolReply{OutputJSON: `{"exit_code":0}`, ToolCallID: "call-77"}}
	env.srv.WithSandboxTools(fake)

	resp, err := env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-9"))
	require.NoError(t, err)
	assert.Equal(t, []string{"test-tenant|mission-7|run-1|scan-agent|task-3|skill-script"}, fake.calls)
	assert.JSONEq(t, `{"target":"web-recon/scripts/probe.sh"}`, string(fake.input))
	assert.JSONEq(t, `{"exit_code":0}`, resp.GetOutputJson())
	assert.Nil(t, resp.GetError())
	assert.Equal(t, "call-77", resp.GetToolCallId(), "the reply must carry the id of the flight recorder record")
	assert.Empty(t, env.recorded, "the daemon path writes the record, and the server writes no second one")
}

// A refusal of the call is a reply with an error, so the agent reads why, and
// the record holds the refusal.
func TestCallTool_ASandboxedToolRefusalIsAReplyWithAnError(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	env.bindAgent(t, "work-9", "scan-agent", "task-3")
	env.srv.WithSandboxTools(&fakeSandboxTools{reply: SandboxToolReply{ErrorCode: "SANDBOX_POLICY_DENIED", ErrorMessage: "the caller may not load the Agent Skill", ToolCallID: "call-78"}})

	resp, err := env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-9"))
	require.NoError(t, err)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, "[SANDBOX_POLICY_DENIED]", resp.GetError().GetCode())
	assert.Contains(t, resp.GetError().GetMessage(), "may not load")
	assert.Empty(t, resp.GetOutputJson())
	assert.Equal(t, "call-78", resp.GetToolCallId(), "a refused call is recorded too")
}

func TestCallTool_ASandboxedToolNeedsARunAnAgentNodeAndACaller(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	env.bindAgent(t, "work-9", "scan-agent", "task-3")

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

	// Work that is not agent work has no node, so the scope of its network is
	// unknown, and the call is refused.
	env.claim(t, "work-10", "agent_principal:42")
	_, err = env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-10"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Empty(t, fake.calls)

	// A failure of the caller itself.
	fake.err = errors.New("no harness factory")
	_, err = env.srv.CallTool(agentCtx("agent_principal:42"), scriptReq("work-9"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// Enqueue binds the agent and the task of agent work, and only of agent work.
func TestWorkAgent_BoundByEnqueueForAgentWorkOnly(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	client := env.reg.stateClient.Client()
	ctx := context.Background()
	item := WorkItem{WorkID: "w-agent", Context: map[string]string{WorkTaskContextKey: "task-9"}}
	require.NoError(t, bindWorkAgent(ctx, client, "agent", "scan-agent", item))
	agent, task, err := env.reg.WorkAgent(ctx, "w-agent")
	require.NoError(t, err)
	assert.Equal(t, "scan-agent", agent)
	assert.Equal(t, "task-9", task)

	toolItem := WorkItem{WorkID: "w-tool"}
	require.NoError(t, bindWorkAgent(ctx, client, "tool", "nmap", toolItem))
	_, _, err = env.reg.WorkAgent(ctx, "w-tool")
	assert.ErrorIs(t, err, ErrWorkAgentUnknown, "tool work binds no agent")
	_, _, err = env.reg.WorkAgent(ctx, "")
	assert.ErrorIs(t, err, ErrWorkAgentUnknown)
	require.NoError(t, client.Set(ctx, workAgentKey("w-bad"), "not json", workOwnerTTL).Err())
	_, _, err = env.reg.WorkAgent(ctx, "w-bad")
	assert.ErrorIs(t, err, ErrWorkAgentUnknown)
}

// Enqueue itself binds the agent of agent work to the work id.
func TestEnqueue_BindsTheAgentOfAgentWork(t *testing.T) {
	env := newWorkIDEnv(t)
	ctx := context.Background()
	_, err := env.queue.Enqueue(ctx, victimTenant, "agent", "scan-agent", WorkItem{
		WorkID: "agent-work-5", WorkType: "execute", Context: map[string]string{WorkTaskContextKey: "task-5"},
	})
	require.NoError(t, err)
	agent, task, err := NewRedisWorkContextRegistry(env.state).WorkAgent(ctx, "agent-work-5")
	require.NoError(t, err)
	assert.Equal(t, "scan-agent", agent)
	assert.Equal(t, "task-5", task)
}
