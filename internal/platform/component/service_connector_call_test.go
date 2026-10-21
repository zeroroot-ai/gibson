// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type fakeConnectorCaller struct {
	calls  []string
	result any
	err    error
}

func (f *fakeConnectorCaller) CallConnectorTool(_ context.Context, tenant, connector, tool string, _ map[string]any) (any, error) {
	f.calls = append(f.calls, tenant+"|"+connector+"|"+tool)
	return f.result, f.err
}

func agentCtx(subject string) context.Context {
	tenant, err := auth.NewTenantID("test-tenant")
	if err != nil {
		panic(err)
	}
	return auth.WithIdentity(auth.ContextWithTenantString(context.Background(), "test-tenant"),
		auth.Identity{Subject: subject, Tenant: tenant, CredentialType: auth.CredentialCapabilityGrant})
}

type connectorEnv struct {
	srv    *ComponentServiceServer
	rec    *audittest.Recorder
	caller *fakeConnectorCaller
	reg    *RedisWorkContextRegistry
	policy metatool.MissionPolicy
}

// newConnectorEnv wires a server for connector calls over a real work context
// registry on miniredis.
func newConnectorEnv(t *testing.T, allow bool, durable func(*audittest.Recorder) audit.DurableWriter) *connectorEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	env := &connectorEnv{rec: &audittest.Recorder{}, caller: &fakeConnectorCaller{result: map[string]any{"name": "demo"}}, reg: NewRedisWorkContextRegistry(sc)}
	az := &allowAuthorizer{allow: map[string]bool{}}
	if allow {
		az.allow["can_execute:"+authz.ConnectorComponentObject("gitlab")] = true
	}
	var writer audit.DurableWriter = env.rec
	if durable != nil {
		writer = durable(env.rec)
	}
	srv := discoveryServer(&listRegistry{}, az)
	srv.auditLog = newPluginAuditLogger(t, writer)
	srv.WithConnectorCaller(env.caller)
	srv.WithWorkContextRegistry(env.reg)
	srv.WithMissionContextResolver(NewMissionContextResolver(sc, nil))
	srv.WithMissionPolicy(func(context.Context, string) (metatool.MissionPolicy, error) { return env.policy, nil })
	env.srv = srv
	return env
}

// claim records a work item of mission m1 and run run-1 that subject claimed.
func (e *connectorEnv) claim(t *testing.T, workID, subject string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, e.reg.RegisterWorkContext(ctx, workID, "mission-7", "test-tenant"))
	require.NoError(t, e.reg.stateClient.Client().Set(ctx, workOwnerKey(workID), "test-tenant", workOwnerTTL).Err())
	require.NoError(t, e.reg.stateClient.Client().Set(ctx, workRunKey(workID), "run-1", workOwnerTTL).Err())
	require.NoError(t, e.reg.BindWorkClaim(ctx, workID, subject))
}

func connectorReq(workID string) *componentpb.CallToolRequest {
	return &componentpb.CallToolRequest{ToolName: "mcp:gitlab:get_project", InputJson: `{"id":"g/p"}`, WorkId: workID}
}

// records returns the result and the details of each audit record.
func records(t *testing.T, rec *audittest.Recorder) []struct {
	Result  string         `json:"result"`
	Details map[string]any `json:"details"`
} {
	t.Helper()
	var out []struct {
		Result  string         `json:"result"`
		Details map[string]any `json:"details"`
	}
	for _, ev := range rec.Events() {
		var m struct {
			Result  string         `json:"result"`
			Details map[string]any `json:"details"`
		}
		require.NoError(t, json.Unmarshal(ev.Metadata, &m))
		out = append(out, m)
	}
	return out
}

// A connector call by an agent writes an intent record and a result record:
// the actor is the agent principal with the source agent, the target is the
// connector, and a call that names a work item that the caller claimed names
// the mission of that work.
func TestCallTool_ConnectorCallWritesIntentThenResult(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")

	resp, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-9"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"demo"}`, resp.GetOutputJson())
	assert.Equal(t, []string{"test-tenant|gitlab|get_project"}, env.caller.calls)

	events := env.rec.Events()
	require.Len(t, events, 2)
	for _, ev := range events {
		assert.Equal(t, "agent", ev.ActorType)
		assert.Equal(t, "agent_principal:42", ev.ActorID)
		assert.Equal(t, "connector.tool.call", ev.Action)
		assert.Equal(t, "connector", ev.TargetType)
		assert.Equal(t, "gitlab", ev.TargetID)
	}
	recs := records(t, env.rec)
	assert.Equal(t, "intent", recs[0].Result)
	assert.Equal(t, "success", recs[1].Result)
	assert.Equal(t, "mission-7", recs[1].Details["mission_id"])
	assert.Equal(t, "work-9", recs[1].Details["work_id"])
	assert.Equal(t, "get_project", recs[1].Details["tool"])
}

// A call with no work id carries no mission id.
func TestCallTool_ConnectorCallWithoutAWorkIDHasNoMission(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq(""))
	require.NoError(t, err)
	for _, ev := range env.rec.Events() {
		assert.NotContains(t, string(ev.Metadata), "mission_id")
	}
}

// An agent must not name the work id of another principal. The id of a work
// item that another component claimed is refused, nothing is dispatched, and no
// record holds the mission of that work.
func TestCallTool_AForeignWorkIDIsRefused(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")

	_, err := env.srv.CallTool(agentCtx("agent_principal:99"), connectorReq("work-9"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, env.caller.calls)
	assert.Empty(t, env.rec.Events())

	// An id that nothing claimed is refused in the same way.
	_, err = env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-unknown"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// A tool on the mission deny list is refused through CallTool, before any
// record and before the connector.
func TestCallTool_ABlockedToolIsRefused(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	env.policy = metatool.MissionPolicy{Blocked: []string{"mcp:gitlab:get_project"}}

	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-9"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, env.caller.calls)
	assert.Empty(t, env.rec.Events())
}

// A run that is not active may not call a connector tool.
func TestCallTool_AnInactiveRunIsRefused(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	env.policy = metatool.MissionPolicy{RunActive: func(context.Context) error { return metatool.ErrRunInactive }}

	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-9"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, env.caller.calls)
}

// A write failure of the intent record refuses the call: no call happens
// without a record.
func TestCallTool_AnAuditWriteFailureRefusesTheCall(t *testing.T) {
	env := newConnectorEnv(t, true, func(r *audittest.Recorder) audit.DurableWriter { return &refusingWriter{} })
	env.claim(t, "work-9", "agent_principal:42")

	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-9"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Empty(t, env.caller.calls)
}

// A server with no audit logger refuses a connector call.
func TestCallTool_ConnectorCallWithNoAuditLoggerIsRefused(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.srv.auditLog = nil
	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq(""))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Empty(t, env.caller.calls)
}

// A denied call reaches no connector, returns PermissionDenied, and its result
// record is a failure with a class and no text.
func TestCallTool_ConnectorCallDeniedIsRecordedAndNotCalled(t *testing.T) {
	env := newConnectorEnv(t, false, nil)
	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq(""))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, env.caller.calls)
	recs := records(t, env.rec)
	require.Len(t, recs, 2)
	assert.Equal(t, "failure", recs[1].Result)
	assert.Equal(t, "unauthorized", recs[1].Details["error"])
}

// A failed connector call is recorded as a failure and returns the error in the
// response. The record holds a class of the error, not its text.
func TestCallTool_ConnectorCallFailureIsRecorded(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.caller.err = errors.New("upstream said: token ghp_SECRET")
	resp, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq(""))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetError())
	events := env.rec.Events()
	require.Len(t, events, 2)
	assert.Contains(t, string(events[1].Metadata), `"result":"failure"`)
	assert.NotContains(t, string(events[1].Metadata), "ghp_SECRET")
}

// SubmitResult and CallTool use one claim check: a result for a work item that
// another component claimed is refused.
func TestSubmitResult_AForeignClaimantIsRefused(t *testing.T) {
	env := newWorkIDEnv(t)
	workID := env.enqueueFor(t, victimTenant, "work-claimed-1")
	_ = env.claimedBy(t, auth.ContextWithTenantString(context.Background(), victimTenant), workID, "component-1")

	other := withSubject(auth.ContextWithTenantString(context.Background(), victimTenant), "component-2")
	_, err := env.svc.SubmitResult(other, &componentpb.SubmitResultRequest{WorkId: workID, Result: []byte(`{}`)})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, env.mr.Exists(resultKey(victimTenant, workID)), "a foreign result must not be stored")

	// A caller with no identity is refused as well.
	_, err = env.svc.SubmitResult(auth.ContextWithTenantString(context.Background(), victimTenant),
		&componentpb.SubmitResultRequest{WorkId: workID, Result: []byte(`{}`)})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
