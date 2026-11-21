// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// stubHarness answers CallToolProto and nothing else.
type stubHarness struct {
	harness.AgentHarness
	call func(name string, req *componentpb.CallToolRequest, resp *componentpb.CallToolResponse) error
}

func (s stubHarness) CallToolProto(_ context.Context, name string, req, resp proto.Message) error {
	return s.call(name, req.(*componentpb.CallToolRequest), resp.(*componentpb.CallToolResponse))
}

// stubFactory makes the stub harness and records what it was asked for.
type stubFactory struct {
	harness.HarnessFactoryInterface
	h       harness.AgentHarness
	err     error
	agent   string
	mission harness.MissionContext
}

func (f *stubFactory) Create(agent string, m harness.MissionContext, _ harness.TargetInfo) (harness.AgentHarness, error) {
	f.agent, f.mission = agent, m
	return f.h, f.err
}

func adapterWith(f harness.HarnessFactoryInterface) sandboxToolAdapter {
	return sandboxToolAdapter{d: &daemonImpl{infrastructure: &Infrastructure{harnessFactory: f}}}
}

func TestSandboxToolAdapter_RunsTheToolWithTheHarnessOfTheRun(t *testing.T) {
	missionID := types.NewID()
	f := &stubFactory{h: stubHarness{call: func(name string, req *componentpb.CallToolRequest, resp *componentpb.CallToolResponse) error {
		assert.Equal(t, "skill-script", name)
		assert.JSONEq(t, `{"target":"s/scripts/a.sh"}`, req.GetInputJson())
		resp.OutputJson = `{"exit_code":0}`
		return nil
	}}}
	ctx := auth.WithIdentity(auth.ContextWithTenantString(context.Background(), "acme"), auth.Identity{Subject: "agent_principal:scan-agent"})
	reply, err := adapterWith(f).CallSandboxedTool(ctx, "acme", missionID.String(), "run-1", "skill-script", []byte(`{"target":"s/scripts/a.sh"}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"exit_code":0}`, reply.OutputJSON)
	assert.Empty(t, reply.ErrorCode)
	assert.Equal(t, "scan-agent", f.agent)
	assert.Equal(t, missionID, f.mission.ID)
	assert.Equal(t, "acme", f.mission.TenantID)
	assert.Equal(t, "run-1", f.mission.MissionRunID)
}

func TestSandboxToolAdapter_AFailureOfTheCallIsAReplyWithAnError(t *testing.T) {
	missionID := types.NewID().String()
	denied := stubHarness{call: func(string, *componentpb.CallToolRequest, *componentpb.CallToolResponse) error {
		return types.WrapError(types.SANDBOX_POLICY_DENIED, "the caller may not load the Agent Skill", nil)
	}}
	reply, err := adapterWith(&stubFactory{h: denied}).CallSandboxedTool(context.Background(), "acme", missionID, "run-1", "skill-script", []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, string(types.SANDBOX_POLICY_DENIED), reply.ErrorCode)
	assert.Contains(t, reply.ErrorMessage, "may not load")

	plain := stubHarness{call: func(string, *componentpb.CallToolRequest, *componentpb.CallToolResponse) error {
		return errors.New("boom")
	}}
	reply, err = adapterWith(&stubFactory{h: plain}).CallSandboxedTool(context.Background(), "acme", missionID, "run-1", "skill-script", []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, "TOOL_FAILED", reply.ErrorCode)

	withErr := stubHarness{call: func(_ string, _ *componentpb.CallToolRequest, resp *componentpb.CallToolResponse) error {
		resp.Error = &componentpb.ComponentError{Code: "EXECUTE_ERROR", Message: "the script failed"}
		return nil
	}}
	reply, err = adapterWith(&stubFactory{h: withErr}).CallSandboxedTool(context.Background(), "acme", missionID, "run-1", "skill-script", []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, "EXECUTE_ERROR", reply.ErrorCode)
	assert.Equal(t, "the script failed", reply.ErrorMessage)
}

func TestSandboxToolAdapter_ErrorsOfTheCallItself(t *testing.T) {
	ctx := context.Background()
	_, err := sandboxToolAdapter{d: &daemonImpl{}}.CallSandboxedTool(ctx, "acme", types.NewID().String(), "r", "skill-script", nil)
	require.Error(t, err, "a daemon with no factory")
	_, err = adapterWith(&stubFactory{}).CallSandboxedTool(ctx, "acme", "not-an-id", "r", "skill-script", nil)
	require.Error(t, err, "a mission id that is not an id")
	_, err = adapterWith(&stubFactory{err: errors.New("no config")}).CallSandboxedTool(ctx, "acme", types.NewID().String(), "r", "skill-script", nil)
	require.Error(t, err, "a factory that fails")
}

func TestCallerAgentName(t *testing.T) {
	withSubject := func(s string) context.Context {
		return auth.WithIdentity(context.Background(), auth.Identity{Subject: s})
	}
	assert.Equal(t, "scan-agent", callerAgentName(withSubject("agent_principal:scan-agent")))
	assert.Equal(t, "agent", callerAgentName(withSubject("user:42")))
	assert.Equal(t, "agent", callerAgentName(withSubject("agent_principal:")))
	assert.Equal(t, "agent", callerAgentName(context.Background()))
}

// While the brain registry is not built, the sink refuses each load, so a
// skill-script call is refused and no load goes without its record.
func TestSkillLoadSink_RefusesUntilTheBrainIsBuilt(t *testing.T) {
	sink := (&daemonImpl{}).skillLoadSink()
	require.NotNil(t, sink)
	require.Error(t, sink(context.Background(), "acme", harness.SkillLoadRecord{Name: "s", Digest: "sha256:aa"}))
}
