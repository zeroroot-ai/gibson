// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

type failingAuthzStore struct{}

func (failingAuthzStore) Get(context.Context, string) (*RunAuthzState, error) {
	return nil, errors.New("not found")
}

// The manager setters and accessors reach the one callback service.
func TestCallbackManager_ConnectorSetters(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{ServiceOptions: []CallbackServiceOption{testEventBus()}, ListenAddress: "127.0.0.1:0"}, slog.Default())

	m.SetConnectorAudit(newConnectorAudit(t, &audittest.Recorder{}))
	if m.server.service.connectorAudit == nil {
		t.Fatal("SetConnectorAudit must reach the service")
	}
	m.SetMissionBlockedTools(func(context.Context, string, string) ([]string, error) { return []string{"x"}, nil })
	m.SetAuthzStore(fakeSearchAuthzStore{state: &RunAuthzState{RunID: "r1", MissionID: "m1", TenantID: "acme", Status: "active"}})

	policy, err := m.MissionPolicyForRun(context.Background(), "acme", "r1")
	if err != nil || len(policy.Blocked) != 1 || policy.CheckRun(context.Background()) != nil {
		t.Fatalf("policy = %+v, err = %v", policy, err)
	}

	var got []ToolCallRecord
	m.SetToolCallSink(func(_ context.Context, _ string, call ToolCallRecord) { got = append(got, call) })
	m.RecordToolCall(testCtxWithTenant(), metatool.CallRecord{Canonical: "mcp:gitlab:x", MissionID: "m1", RunID: "r1", ArgsJSON: []byte(`{}`)}, []byte(`{"ok":1}`), "")
	if len(got) != 1 || got[0].ToolName != "mcp:gitlab:x" || got[0].MissionRunID != "r1" || got[0].Result != `{"ok":1}` {
		t.Fatalf("recorded = %+v", got)
	}
}

// Each way that the policy of a run cannot be built is an error, and an inactive
// run fails its check.
func TestMissionPolicyForRun_Refusals(t *testing.T) {
	ctx := context.Background()
	svc := &HarnessCallbackService{logger: slog.Default()}
	if _, err := svc.MissionPolicyForRun(ctx, "acme", "r1"); err == nil {
		t.Error("no authz store: want an error")
	}
	svc.authzStore = failingAuthzStore{}
	if _, err := svc.MissionPolicyForRun(ctx, "acme", "r1"); err == nil {
		t.Error("an unreadable run: want an error")
	}
	svc.authzStore = fakeSearchAuthzStore{state: &RunAuthzState{RunID: "r1", MissionID: "", TenantID: "acme", Status: "active"}}
	svc.missionBlockedTools = noBlockedTools
	if _, err := svc.MissionPolicyForRun(ctx, "acme", "r1"); err == nil {
		t.Error("a run that names no mission: want an error")
	}
	svc.authzStore = fakeSearchAuthzStore{state: &RunAuthzState{RunID: "r1", MissionID: "m1", TenantID: "acme", Status: "completed"}}
	policy, err := svc.MissionPolicyForRun(ctx, "acme", "r1")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := policy.CheckRun(ctx); !errors.Is(err, metatool.ErrRunInactive) {
		t.Errorf("a completed run: err = %v, want ErrRunInactive", err)
	}
	svc.missionBlockedTools = nil
	if _, err := svc.policyFromState(ctx, &RunAuthzState{MissionID: "m1"}); err == nil {
		t.Error("no source: want an error")
	}

	// The callback names no mission.
	svc.missionBlockedTools = noBlockedTools
	if _, err := svc.storedBlockedTools(ctx, &harnesspb.ContextInfo{}); err == nil {
		t.Error("a callback with no mission: want an error")
	}
}

// invoke_tool of a completed run, and a search of a completed run, are refused.
func TestMetaTools_ACompletedRunIsRefused(t *testing.T) {
	svc, ci, called := storedPolicySvc(t, noBlockedTools)
	svc.authzStore = fakeSearchAuthzStore{state: &RunAuthzState{RunID: "run-1", MissionID: "mission-1", UserID: "alice", TenantID: "test-tenant", Status: "completed"}}
	for _, name := range []string{metatool.InvokeToolName, metatool.SearchToolsName} {
		resp, err := svc.CallToolProto(testCtxWithTenant(), &harnesspb.CallToolProtoRequest{
			Context: ci, Name: name, InputJson: []byte(`{"id":"mcp:gitlab:create_issue","query":"x"}`),
		})
		if err != nil || resp.GetError().GetCode() != commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
			t.Errorf("%s: resp = %v, err = %v; want PERMISSION_DENIED", name, resp, err)
		}
	}
	if len(*called) != 0 {
		t.Errorf("a completed run reached the connector: %v", *called)
	}
}

// A policy that cannot be loaded refuses invoke_tool and the search.
func TestMetaTools_AnUnloadablePolicyIsRefused(t *testing.T) {
	svc, ci, _ := storedPolicySvc(t, nil)
	resp, err := svc.CallToolProto(testCtxWithTenant(), &harnesspb.CallToolProtoRequest{
		Context: ci, Name: metatool.SearchToolsName, InputJson: []byte(`{"query":"x"}`),
	})
	if err != nil || resp.GetError().GetCode() != commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE {
		t.Fatalf("resp = %v, err = %v; want UNAVAILABLE", resp, err)
	}
}

// The audit context takes the user of the run as the actor when the callback
// carries no identity, and leaves a context with an identity alone.
func TestAuditCtx(t *testing.T) {
	rec := metatool.CallRecord{Tenant: "acme", Subject: "user:alice"}
	if ctx := auditCtx(context.Background(), rec); ctx == context.Background() {
		t.Error("a context with no identity must gain one")
	}
	if ctx := auditCtx(context.Background(), metatool.CallRecord{Tenant: "bad tenant!", Subject: "user:a"}); ctx != context.Background() {
		t.Error("a tenant that does not parse leaves the context as it is")
	}
	withID := auditCtx(context.Background(), rec)
	if got := auditCtx(withID, metatool.CallRecord{Tenant: "acme", Subject: "user:other"}); got != withID {
		t.Error("a context with an identity must not change")
	}
}

// A malformed id that the check let through, and a flattened native id, take
// the native path or an invalid-argument answer.
func TestMetaInvoke_ANativeIDInTheFlattenedFormReachesTheNativePath(t *testing.T) {
	var captured []capturedTool
	svc, harness, ci := newNativeMetaSvc(t, &captured, nil)
	svc.missionBlockedTools = noBlockedTools
	svc.connectorAudit = newConnectorAudit(t, &audittest.Recorder{})
	h := metatool.NewHandler(nil, mtAuthz{allow: map[string]bool{"native:test-external-tool": true}}, nil)
	resp, err := svc.metaInvoke(testCtxWithTenant(), ci, h, harness, catalog.Caller{Subject: "user:u-1", Tenant: "test-tenant"}, metatool.MissionPolicy{},
		[]byte(`{"id":"native__test-external-tool","args":{}}`))
	if err != nil {
		t.Fatalf("metaInvoke: %v", err)
	}
	if resp.GetError() != nil && resp.GetError().GetCode() == commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("the flattened native id was refused: %v", resp.GetError())
	}
}
