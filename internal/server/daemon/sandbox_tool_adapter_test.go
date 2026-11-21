// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

type stubPullTool struct {
	resp *harnesspb.CallToolProtoResponse
	err  error
	got  string
}

func (s *stubPullTool) CallPullTool(_ context.Context, tenant, mission, run, agent, task, name string, input []byte) (*harnesspb.CallToolProtoResponse, error) {
	s.got = tenant + "|" + mission + "|" + run + "|" + agent + "|" + task + "|" + name + "|" + string(input)
	return s.resp, s.err
}

func TestSandboxToolAdapter_MapsTheReplyOfTheCallbackPath(t *testing.T) {
	stub := &stubPullTool{resp: &harnesspb.CallToolProtoResponse{OutputJson: []byte(`{"exit_code":0}`), ToolCallId: "call-1"}}
	reply, err := sandboxToolAdapter{svc: stub}.CallSandboxedTool(context.Background(), "acme", "m1", "r1", "agent-a", "t1", "skill-script", []byte(`{}`))
	require.NoError(t, err)
	assert.Equal(t, "acme|m1|r1|agent-a|t1|skill-script|{}", stub.got)
	assert.JSONEq(t, `{"exit_code":0}`, reply.OutputJSON)
	assert.Equal(t, "call-1", reply.ToolCallID)
	assert.Empty(t, reply.ErrorCode)

	stub.resp = &harnesspb.CallToolProtoResponse{
		Error:      &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Message: "tool is blocked by mission policy"},
		ToolCallId: "call-2",
	}
	reply, err = sandboxToolAdapter{svc: stub}.CallSandboxedTool(context.Background(), "acme", "m1", "r1", "agent-a", "t1", "skill-script", nil)
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED.String(), reply.ErrorCode)
	assert.Contains(t, reply.ErrorMessage, "blocked")
	assert.Equal(t, "call-2", reply.ToolCallID)

	stub.err = errors.New("no harness for the node")
	_, err = sandboxToolAdapter{svc: stub}.CallSandboxedTool(context.Background(), "acme", "m1", "r1", "agent-a", "t1", "skill-script", nil)
	require.Error(t, err)
}

// While the brain registry is not built, the sink refuses each load, so a
// skill-script call is refused and no load goes without its record.
func TestSkillLoadSink_RefusesUntilTheBrainIsBuilt(t *testing.T) {
	sink := (&daemonImpl{}).skillLoadSink()
	require.NotNil(t, sink)
	require.Error(t, sink(context.Background(), "acme", harness.SkillLoadRecord{Name: "s", Digest: "sha256:aa"}))
}
