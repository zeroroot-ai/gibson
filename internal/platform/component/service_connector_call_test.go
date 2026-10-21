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

	"github.com/zeroroot-ai/gibson/internal/engine/state"
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

// connectorCallServer wires a server for connector calls. The returned miniredis
// holds the work context of the mission lookup.
func connectorCallServer(t *testing.T, allow bool, caller *fakeConnectorCaller) (*ComponentServiceServer, *audittest.Recorder, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	rec := &audittest.Recorder{}
	az := &allowAuthorizer{allow: map[string]bool{}}
	if allow {
		az.allow["can_execute:"+authz.ConnectorComponentObject("gitlab")] = true
	}
	srv := discoveryServer(&listRegistry{}, az)
	srv.auditLog = newPluginAuditLogger(t, rec)
	srv.WithConnectorCaller(caller)
	srv.WithMissionContextResolver(NewMissionContextResolver(sc, nil))
	return srv, rec, mr
}

// A connector tool call by an agent writes one audit record: the actor is the
// agent principal with the source agent, the target is the connector, and a
// call with a work id names the mission of that work.
func TestCallTool_ConnectorCallWritesAnAuditRecord(t *testing.T) {
	caller := &fakeConnectorCaller{result: map[string]any{"name": "demo"}}
	srv, rec, mr := connectorCallServer(t, true, caller)
	mr.HSet(workContextKeyPrefix+"work-9", workContextMissionField, "mission-7", workContextTenantField, "test-tenant")

	resp, err := srv.CallTool(agentCtx("agent_principal:42"), &componentpb.CallToolRequest{
		ToolName: "mcp:gitlab:get_project", InputJson: `{"id":"g/p"}`, WorkId: "work-9",
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"demo"}`, resp.GetOutputJson())
	assert.Equal(t, []string{"test-tenant|gitlab|get_project"}, caller.calls)

	events := rec.Events()
	require.Len(t, events, 1)
	ev := events[0]
	assert.Equal(t, "agent", ev.ActorType)
	assert.Equal(t, "agent_principal:42", ev.ActorID)
	assert.Equal(t, "connector.tool.call", ev.Action)
	assert.Equal(t, "connector", ev.TargetType)
	assert.Equal(t, "gitlab", ev.TargetID)

	var meta struct {
		Result  string         `json:"result"`
		Details map[string]any `json:"details"`
	}
	require.NoError(t, json.Unmarshal(ev.Metadata, &meta))
	assert.Equal(t, "success", meta.Result)
	assert.Equal(t, "mission-7", meta.Details["mission_id"])
	assert.Equal(t, "get_project", meta.Details["tool"])
}

// A call with no work id carries no mission id.
func TestCallTool_ConnectorCallWithoutAWorkIDHasNoMission(t *testing.T) {
	srv, rec, _ := connectorCallServer(t, true, &fakeConnectorCaller{result: "ok"})
	_, err := srv.CallTool(agentCtx("agent_principal:42"), &componentpb.CallToolRequest{
		ToolName: "mcp:gitlab:get_project", InputJson: `{}`,
	})
	require.NoError(t, err)
	events := rec.Events()
	require.Len(t, events, 1)
	assert.NotContains(t, string(events[0].Metadata), "mission_id")
}

// A denied call reaches no connector, returns PermissionDenied, and is recorded
// as a failure.
func TestCallTool_ConnectorCallDeniedIsRecordedAndNotCalled(t *testing.T) {
	caller := &fakeConnectorCaller{}
	srv, rec, _ := connectorCallServer(t, false, caller)
	_, err := srv.CallTool(agentCtx("agent_principal:42"), &componentpb.CallToolRequest{
		ToolName: "mcp:gitlab:get_project", InputJson: `{}`,
	})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, caller.calls)
	events := rec.Events()
	require.Len(t, events, 1)
	assert.Contains(t, string(events[0].Metadata), `"result":"failure"`)
	assert.Contains(t, string(events[0].Metadata), "unauthorized")
}

// A failed connector call is recorded as a failure and returns the error in
// the response. The audit record holds a class of the error, not its text.
func TestCallTool_ConnectorCallFailureIsRecorded(t *testing.T) {
	caller := &fakeConnectorCaller{err: errors.New("upstream said: token ghp_SECRET")}
	srv, rec, _ := connectorCallServer(t, true, caller)
	resp, err := srv.CallTool(agentCtx("agent_principal:42"), &componentpb.CallToolRequest{
		ToolName: "mcp:gitlab:get_project", InputJson: `{}`,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp.GetError())
	events := rec.Events()
	require.Len(t, events, 1)
	assert.Contains(t, string(events[0].Metadata), `"result":"failure"`)
	assert.NotContains(t, string(events[0].Metadata), "ghp_SECRET")
}

// A server with no audit logger refuses a connector call: no call happens
// without a record.
func TestCallTool_ConnectorCallWithNoAuditLoggerIsRefused(t *testing.T) {
	caller := &fakeConnectorCaller{}
	srv, _, _ := connectorCallServer(t, true, caller)
	srv.auditLog = nil
	_, err := srv.CallTool(agentCtx("agent_principal:42"), &componentpb.CallToolRequest{
		ToolName: "mcp:gitlab:get_project", InputJson: `{}`,
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Empty(t, caller.calls)
}
