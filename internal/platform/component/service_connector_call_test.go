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
	"google.golang.org/grpc/metadata"
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
	// policyRuns lists the runs whose policy the server read.
	policyRuns []string
	// policyErr makes the source of the policy fail.
	policyErr error
	// recorded holds the flight recorder records of the calls.
	recorded []metatool.CallRecord
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
	srv.WithMissionPolicy(func(_ context.Context, _, run string) (metatool.MissionPolicy, error) {
		env.policyRuns = append(env.policyRuns, run)
		return env.policy, env.policyErr
	})
	srv.WithToolCallRecorder(func(_ context.Context, rec metatool.CallRecord, _ []byte, _ string) {
		env.recorded = append(env.recorded, rec)
	})
	srv.WithGrantVerifier(fakeGrants{})
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

type auditRecord struct {
	Result  string         `json:"result"`
	Details map[string]any `json:"details"`
}

// records returns the result and the details of each audit record.
func records(t *testing.T, rec *audittest.Recorder) []auditRecord {
	t.Helper()
	out := make([]auditRecord, 0, len(rec.Events()))
	for _, ev := range rec.Events() {
		var m auditRecord
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
	env := newConnectorEnv(t, true, func(*audittest.Recorder) audit.DurableWriter { return &refusingWriter{} })
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
	_ = env.claimedBy(auth.ContextWithTenantString(context.Background(), victimTenant), t, workID, "component-1")

	other := withSubject(auth.ContextWithTenantString(context.Background(), victimTenant), "component-2")
	_, err := env.svc.SubmitResult(other, &componentpb.SubmitResultRequest{WorkId: workID, Result: []byte(`{}`)})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, env.mr.Exists(resultKey(victimTenant, workID)), "a foreign result must not be stored")

	// A caller with no identity is refused as well.
	_, err = env.svc.SubmitResult(auth.ContextWithTenantString(context.Background(), victimTenant),
		&componentpb.SubmitResultRequest{WorkId: workID, Result: []byte(`{}`)})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// CallTool writes the flight recorder record of a connector call, ADR-0131: for
// a success, with the mission and the run of the work item, and for a denial.
func TestCallTool_ConnectorCallIsRecordedByTheFlightRecorder(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-9"))
	require.NoError(t, err)
	require.Len(t, env.recorded, 1)
	assert.Equal(t, "mcp:gitlab:get_project", env.recorded[0].Canonical)
	assert.Equal(t, "mission-7", env.recorded[0].MissionID)
	assert.Equal(t, "run-1", env.recorded[0].RunID)

	denied := newConnectorEnv(t, false, nil)
	_, err = denied.srv.CallTool(agentCtx("agent_principal:42"), connectorReq(""))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Len(t, denied.recorded, 1, "a denied call is recorded too")

	// A server with no recorder refuses the call.
	env.srv.toolCallRecorder = nil
	_, err = env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq(""))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// A verified task grant that names a run brings the policy of that run even
// when the request names no work id: a blocked tool is refused.
func TestCallTool_AGrantThatNamesARunBringsItsPolicy(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.policy = metatool.MissionPolicy{Blocked: []string{"mcp__gitlab__get_project"}}

	ctx := grantedCtx(agentCtx("agent_principal:42"), "mission-7", "run-1")
	_, err := env.srv.CallTool(ctx, connectorReq(""))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, []string{"run-1"}, env.policyRuns)
	assert.Empty(t, env.caller.calls)

	// An inactive run is refused too.
	env.policy = metatool.MissionPolicy{RunActive: func(context.Context) error { return metatool.ErrRunInactive }}
	_, err = env.srv.CallTool(ctx, connectorReq(""))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// A call with no work id and no run in the grant keeps the can_execute check
// only: the policy is not read. A component grant names no run.
func TestCallTool_ACallWithNoRunKeepsCanExecuteOnly(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.policy = metatool.MissionPolicy{Blocked: []string{"mcp:gitlab:get_project"}}
	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq(""))
	require.NoError(t, err)

	component := metadata.NewIncomingContext(agentCtx("agent_principal:42"),
		metadata.Pairs("x-capability-grant", grantToken("component", "", "", "sig")))
	_, err = env.srv.CallTool(component, connectorReq(""))
	require.NoError(t, err)
	assert.Empty(t, env.policyRuns, "no run, so no policy")

	// A task grant that does not verify refuses the call.
	bad := metadata.NewIncomingContext(agentCtx("agent_principal:42"),
		metadata.Pairs("x-capability-grant", grantToken("JWT", "mission-7", "run-1", "foreign")))
	_, err = env.srv.CallTool(bad, connectorReq(""))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// A policy that cannot be read refuses a call that belongs to a run.
func TestCallTool_AnUnreadablePolicyRefusesTheCall(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	env.policyErr = errors.New("store down")
	_, err := env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-9"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Empty(t, env.caller.calls)

	env.policyErr = nil
	env.srv.missionPolicy = nil
	_, err = env.srv.CallTool(agentCtx("agent_principal:42"), connectorReq("work-9"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// A grant and a work item that name different runs are refused.
func TestCallTool_AGrantAndAWorkItemOfDifferentRunsAreRefused(t *testing.T) {
	env := newConnectorEnv(t, true, nil)
	env.claim(t, "work-9", "agent_principal:42")
	ctx := grantedCtx(agentCtx("agent_principal:42"), "mission-7", "run-2")
	_, err := env.srv.CallTool(ctx, connectorReq("work-9"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, env.caller.calls)
}

// PollWork records the principal that claimed the work item. A later call that
// names the work id needs it, so a PollWork that does not record it fails this.
func TestPollWork_RecordsTheClaimant(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.registry = &pollRegistry{info: ComponentInfo{Kind: "tool", Name: "nmap", InstanceID: "inst-own"}}
	_, err := env.queue.Enqueue(context.Background(), victimTenant, "tool", "nmap", WorkItem{
		WorkID: "work-poll-claim", WorkType: "execute", Context: map[string]string{"mission_id": "mission-2"},
	})
	require.NoError(t, err)

	ctx := withSubject(auth.ContextWithTenantString(context.Background(), victimTenant), "agent_principal:poller")
	resp, err := env.svc.PollWork(ctx, &componentpb.PollWorkRequest{InstanceId: "inst-own", TimeoutMs: 100})
	require.NoError(t, err)
	require.Equal(t, "work-poll-claim", resp.WorkId)

	claimant, err := NewRedisWorkContextRegistry(env.state).WorkClaimant(context.Background(), "work-poll-claim")
	require.NoError(t, err)
	assert.Equal(t, "agent_principal:poller", claimant)

	// The poller can then submit its result, and another principal cannot.
	_, err = env.svc.SubmitResult(withSubject(auth.ContextWithTenantString(context.Background(), victimTenant), "agent_principal:other"),
		&componentpb.SubmitResultRequest{WorkId: "work-poll-claim", Result: []byte(`{}`)})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{WorkId: "work-poll-claim", Result: []byte(`{}`)})
	require.NoError(t, err)
}
