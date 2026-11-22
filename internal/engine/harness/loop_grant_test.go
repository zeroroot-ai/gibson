// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// The catalog states the class of each connector: jira is ticket, pagerduty is
// paging and microsoft-sentinel is siem.

type loopFakeMembers struct {
	// runs maps "tenant/run" to "member/bank".
	runs map[string]string
	err  error
}

func (f loopFakeMembers) MemberByRun(_ context.Context, tenant, run string) (memberID, bankID string, err error) {
	if f.err != nil {
		return "", "", f.err
	}
	v, ok := f.runs[tenant+"/"+run]
	if !ok {
		return "", "", ErrNotAMember
	}
	memberID, bankID, _ = strings.Cut(v, "/")
	return memberID, bankID, nil
}

// loopFakeSource keeps the grants of each tenant apart, as the store does.
type loopFakeSource struct {
	grants map[string]*LoopGrant // "tenant/agent"
	err    error
	reads  []string
}

func (f *loopFakeSource) LoopGrantFor(_ context.Context, tenant, agent string) (*LoopGrant, error) {
	f.reads = append(f.reads, tenant+"/"+agent)
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.grants[tenant+"/"+agent]
	if !ok {
		return nil, ErrNoLoopGrant
	}
	return g, nil
}

type loopFixture struct {
	svc       *HarnessCallbackService
	source    *loopFakeSource
	authz     *fakeSearchAuthz
	connected []string
	durable   *audittest.Recorder
	captured  []capturedTool
}

const loopTenantA = "tenant-a"

func newLoopFixture(t *testing.T, grants map[string]*LoopGrant, enabled ...string) *loopFixture {
	t.Helper()
	f := &loopFixture{
		source:  &loopFakeSource{grants: grants},
		durable: &audittest.Recorder{},
	}
	allow := map[string]bool{}
	for _, c := range enabled {
		allow["component:connector/"+c] = true
	}
	f.authz = &fakeSearchAuthz{allow: allow}
	f.svc = &HarnessCallbackService{
		logger:              slog.Default(),
		agentSkills:         noAgentSkillStore,
		skillLoadSink:       noSkillLoadSink,
		componentAuthorizer: f.authz,
		componentRegistry:   fakeSearchReg{},
		// The run authz store must stay unread on the member path. A state
		// with a person in it would show up as the subject of the check.
		authzStore: fakeSearchAuthzStore{state: &RunAuthzState{UserID: "must-not-be-read", TenantID: loopTenantA, Status: "active"}},
		connectors: fakeConnectors{result: map[string]any{"ok": true}, called: &f.connected, tools: []catalog.ToolEntry{
			{Source: toolid.SourceMCP, Connector: "jira", Tool: "create_issue", Description: "open a ticket"},
			{Source: toolid.SourceMCP, Connector: "pagerduty", Tool: "page", Description: "page the on call"},
			{Source: toolid.SourceMCP, Connector: "microsoft-sentinel", Tool: "query", Description: "query the siem"},
		}},
		connectorAudit:      newConnectorAudit(t, f.durable),
		missionBlockedTools: noBlockedTools,
		members: loopFakeMembers{runs: map[string]string{
			loopTenantA + "/run-1": "member-1/bank-1",
			"tenant-b/run-9":       "member-9/bank-9",
		}},
		toolCallSink: func(_ context.Context, tn string, call ToolCallRecord) {
			f.captured = append(f.captured, capturedTool{tenant: tn, call: call})
		},
	}
	WithLoopGrants(f.source)(f.svc)
	return f
}

func loopMemberCtx(t *testing.T, tenant, agent, bank, member, run string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	require.NoError(t, err)
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	return withTaskGrantClaims(ctx, sdkcg.Claims{
		Subject: "component:agent:" + agent, Tenant: tid, MissionID: bank, TaskID: member, MissionRunID: run,
	})
}

func invokeReq(id string) *harnesspb.CallToolProtoRequest {
	return &harnesspb.CallToolProtoRequest{
		Context:   &harnesspb.ContextInfo{MissionId: "bank-1", MissionRunId: "run-1", AgentName: "intake-agent"},
		Name:      metatool.InvokeToolName,
		InputJson: []byte(`{"id":"` + id + `","args":{"title":"x"}}`),
	}
}

func grantOf(id string, classes ...string) *LoopGrant {
	return &LoopGrant{ID: id, AgentName: "intake-agent", ToolClasses: classes, Grantor: "user:admin"}
}

func (f *loopFixture) auditText() string {
	var b strings.Builder
	for _, e := range f.durable.Events() {
		b.WriteString(e.Action + " " + e.Decision + " " + string(e.Metadata) + "\n")
	}
	return b.String()
}

// A grant of a class covers each connector of the class that the tenant
// enabled. The call runs, and the audit record names the grant, the grantor and
// the member.
func TestMemberInvoke_AGrantedClassRunsAndTheRecordNamesGrantAndGrantor(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/intake-agent": grantOf("lg-1", "ticket")}, "jira")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	require.Nil(t, resp.GetError(), "a granted class must run: %v", resp.GetError())
	assert.Equal(t, []string{"tenant-a/jira/create_issue"}, f.connected)

	text := f.auditText()
	assert.Contains(t, text, `"loop_grant_id":"lg-1"`)
	assert.Contains(t, text, `"grantor":"user:admin"`)
	assert.Contains(t, text, `"member_id":"member-1"`)
	// can_execute is checked beside the grant, for the member set of the tenant.
	assert.Equal(t, "tenant:tenant-a#member", f.authz.lastUser)
	assert.NotContains(t, f.authz.lastUser, "must-not-be-read")
}

// The class is read at call time, so a connector of the class that the tenant
// enables later is covered with no change of the grant.
func TestMemberInvoke_AGrantCoversAnotherConnectorOfTheSameClass(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/intake-agent": grantOf("lg-1", "paging")}, "pagerduty")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:pagerduty:page"))
	require.NoError(t, err)
	require.Nil(t, resp.GetError())
}

// A member with no loop grant is refused, and the refusal is recorded.
func TestMemberInvoke_NoGrantIsRefusedAndRecorded(t *testing.T) {
	f := newLoopFixture(t, nil, "jira")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected, "the connector must not be called")
	assert.Len(t, f.captured, 1, "the flight recorder holds the refusal")
	assert.Contains(t, f.auditText(), "no_loop_grant")
}

// A grant of other classes does not cover the connector.
func TestMemberInvoke_AClassThatTheGrantLacksIsRefusedAndRecordsTheGrant(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/intake-agent": grantOf("lg-1", "paging")}, "jira")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
	text := f.auditText()
	assert.Contains(t, text, "no_loop_grant")
	assert.Contains(t, text, `"loop_grant_id":"lg-1"`)
}

// The loop grant sits beside can_execute. A connector that the tenant switched
// off still stops the member, whatever the grant holds.
func TestMemberInvoke_TheTenantSwitchOfAConnectorStillStopsTheMember(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/intake-agent": grantOf("lg-1", "ticket")} /* jira not enabled */)
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
}

// A member of tenant A cannot use a grant of tenant B. The grant of tenant B
// exists for the same agent, and the member of tenant A is still refused.
func TestMemberInvoke_AMemberOfTenantACannotUseTheGrantOfTenantB(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{"tenant-b/intake-agent": grantOf("lg-b", "ticket")}, "jira")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
	assert.Equal(t, []string{"tenant-a/intake-agent"}, f.source.reads, "the grant is read for the tenant of the verified grant only")
}

// A body field cannot name another tenant or member. The tenant and the member
// come from the verified grant of the call.
func TestMemberOfCall_ReadsTheVerifiedGrantAndNotTheBody(t *testing.T) {
	f := newLoopFixture(t, nil)
	m, ok, err := f.svc.memberOfCall(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, memberCall{tenant: loopTenantA, agent: "intake-agent", memberID: "member-1", bankID: "bank-1", runID: "run-1"}, m)

	for name, ctx := range map[string]context.Context{
		"no grant":                       auth.ContextWithTenantString(context.Background(), loopTenantA),
		"a run that backs no member":     loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-404"),
		"a grant of another bank":        loopMemberCtx(t, loopTenantA, "intake-agent", "bank-x", "member-1", "run-1"),
		"a turn grant of the member":     loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "job-7", "run-1"),
		"a run of another tenant":        loopMemberCtx(t, loopTenantA, "intake-agent", "bank-9", "member-9", "run-9"),
		"the grant of a person's sender": withTaskGrantClaims(auth.ContextWithTenantString(context.Background(), loopTenantA), sdkcg.Claims{Subject: "user:alice", MissionRunID: "run-1"}),
	} {
		_, ok, err := f.svc.memberOfCall(ctx)
		require.NoError(t, err, name)
		assert.False(t, ok, name)
	}
}

// An outage of the bank store is no "not a member", and an outage of the grant
// store is no empty grant. Both refuse the call.
func TestMemberInvoke_OutagesRefuse(t *testing.T) {
	f := newLoopFixture(t, nil, "jira")
	f.svc.members = loopFakeMembers{err: errors.New("bank store down")}
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode())

	f = newLoopFixture(t, nil, "jira")
	f.source.err = errors.New("tenant database down")
	resp, err = f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
}

// search_tools shows a member only the tools of the classes of its grant.
func TestMemberSearch_ListsOnlyTheGrantedClasses(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/intake-agent": grantOf("lg-1", "ticket", "paging")},
		"jira", "pagerduty", "microsoft-sentinel")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{MissionId: "bank-1", MissionRunId: "run-1"},
		Name:    metatool.SearchToolsName, InputJson: []byte(`{}`),
	})
	require.NoError(t, err)
	require.Nil(t, resp.GetError())
	out := string(resp.GetOutputJson())
	assert.Contains(t, out, "jira")
	assert.Contains(t, out, "pagerduty")
	assert.NotContains(t, out, "microsoft-sentinel", "the siem class is not granted")
}

func TestMemberSearch_NoGrantIsRefused(t *testing.T) {
	f := newLoopFixture(t, nil, "jira")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{MissionId: "bank-1", MissionRunId: "run-1"},
		Name:    metatool.SearchToolsName, InputJson: []byte(`{}`),
	})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
}

// A loop grant adds the tool call and the granted harness calls to the base
// grant, and nothing else.
func TestMemberLoopGrantRPCs(t *testing.T) {
	assert.Empty(t, MemberLoopGrantRPCs(nil))
	got := MemberLoopGrantRPCs(&LoopGrant{ToolClasses: []string{"ticket"}, HarnessCalls: []string{"SubmitFinding", "GetCredential", "Nope"}})
	assert.Equal(t, []string{
		"/gibson.harness.v1.HarnessCallbackService/CallToolProto",
		"/gibson.harness.v1.HarnessCallbackService/SubmitFinding",
	}, got, "an ungrantable name must be dropped")
	assert.Equal(t, []string{"/gibson.harness.v1.HarnessCallbackService/SubmitFinding"},
		MemberLoopGrantRPCs(&LoopGrant{HarnessCalls: []string{"SubmitFinding"}}))
}

// Each grantable name is a real method of the descriptor.
func TestGrantableMemberHarnessCalls_AreRealMethods(t *testing.T) {
	known := map[string]bool{}
	for _, m := range descriptorMethodNames() {
		known[m] = true
	}
	require.True(t, known[toolCallRPCName])
	for _, name := range GrantableMemberHarnessCalls() {
		assert.True(t, known[name], name)
	}
	// The base grant is not widened.
	for _, rpc := range MemberBaseGrantRPCs() {
		assert.NotEqual(t, toolCallRPCName, methodName(rpc))
	}
}

var _ = component.ComponentInfo{}

func searchReq() *harnesspb.CallToolProtoRequest {
	return &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{MissionId: "bank-1", MissionRunId: "run-1"},
		Name:    metatool.SearchToolsName, InputJson: []byte(`{}`),
	}
}

// An unread grant is not an empty one: search_tools says unavailable.
func TestMemberSearch_AnUnreadGrantIsUnavailable(t *testing.T) {
	f := newLoopFixture(t, nil, "jira")
	f.source.err = errors.New("tenant database down")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), searchReq())
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode())
}

// A daemon with no grant source, and a source that returns nothing, both read as
// no grant.
func TestMemberLoopGrant_NoSourceAndAnEmptyAnswerAreNoGrant(t *testing.T) {
	f := newLoopFixture(t, nil, "jira")
	m := memberCall{tenant: loopTenantA, agent: "intake-agent"}

	f.svc.loopGrants = nil
	_, err := f.svc.loopGrant(context.Background(), m)
	require.ErrorIs(t, err, ErrNoLoopGrant)

	f.svc.loopGrants = nilGrantSource{}
	_, err = f.svc.loopGrant(context.Background(), m)
	require.ErrorIs(t, err, ErrNoLoopGrant)
}

type nilGrantSource struct{}

func (nilGrantSource) LoopGrantFor(context.Context, string, string) (*LoopGrant, error) {
	return nil, nil
}

// A member call of the other meta-tool names, and of a native tool, are refused.
func TestMemberMetaTool_UnknownNameAndNativeToolAreRefused(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/intake-agent": grantOf("lg-1", "ticket")}, "jira")
	ctx := loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1")

	resp, err := f.svc.serveMemberMetaTool(ctx, &harnesspb.CallToolProtoRequest{Name: "other"}, memberCall{
		tenant: loopTenantA, agent: "intake-agent", memberID: "member-1", bankID: "bank-1", runID: "run-1",
	})
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, resp.GetError().GetCode())

	resp, err = f.svc.CallToolProto(ctx, invokeReq("native:nmap"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
}

func TestMemberSearch_HidesSkillsAndNativeTools(t *testing.T) {
	g := grantOf("lg-1", "ticket")
	hidden := memberHidden(g)
	assert.False(t, hidden(toolid.ID{Source: toolid.SourceMCP, Connector: "jira", Tool: "create_issue"}))
	assert.True(t, hidden(toolid.ID{Source: toolid.SourceMCP, Connector: "pagerduty", Tool: "page"}))
	assert.True(t, hidden(toolid.ID{Source: toolid.SourceNative, Tool: "nmap"}))
	assert.True(t, hidden(toolid.ID{Source: toolid.SourceSkill, Tool: "s"}))
}
