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

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
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
	grants map[string]*LoopGrant // "tenant/member"
	err    error
	reads  []string
}

func (f *loopFakeSource) LoopGrantFor(_ context.Context, tenant, member string) (*LoopGrant, error) {
	f.reads = append(f.reads, tenant+"/"+member)
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.grants[tenant+"/"+member]
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

func loopMemberCtx(t *testing.T, tenant, agentName, bank, member, run string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenant)
	require.NoError(t, err)
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	return withTaskGrantClaims(ctx, sdkcg.Claims{
		Subject: "component:agent:" + agentName, Tenant: tid, MissionID: bank, TaskID: member, MissionRunID: run,
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
	return &LoopGrant{ID: id, MemberID: "member-1", AgentName: "intake-agent", ToolClasses: classes, Grantor: "user:admin"}
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
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "ticket")}, "jira")
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
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "paging")}, "pagerduty")
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
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "paging")}, "jira")
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
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "ticket")} /* jira not enabled */)
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
}

// A member of tenant A cannot use a grant of tenant B. The grant of tenant B
// exists for the same agent, and the member of tenant A is still refused.
func TestMemberInvoke_AMemberOfTenantACannotUseTheGrantOfTenantB(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{"tenant-b/member-1": grantOf("lg-b", "ticket")}, "jira")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
	assert.Equal(t, []string{"tenant-a/member-1"}, f.source.reads, "the grant is read for the tenant of the verified grant only")
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
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "ticket", "paging")},
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
	m := memberCall{tenant: loopTenantA, agent: "intake-agent", memberID: "member-1"}

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
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "ticket")}, "jira")
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

// The grant is bound to the member. Another member of the same agent, in the same
// tenant, holds nothing (gibson#1612).
func TestMemberInvoke_AnotherMemberOfTheSameAgentHoldsNoGrant(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "ticket")}, "jira")
	f.svc.members = loopFakeMembers{runs: map[string]string{loopTenantA + "/run-2": "member-2/bank-1"}}
	req := invokeReq("mcp:jira:create_issue")
	req.Context = nil
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-2", "run-2"), req)
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
	assert.Equal(t, []string{"tenant-a/member-2"}, f.source.reads)
}

// A grant of the member that names another agent than the agent of the verified
// grant of the call is no grant.
func TestMemberInvoke_AGrantOfAnotherAgentIsNoGrant(t *testing.T) {
	g := grantOf("lg-1", "ticket")
	g.AgentName = "other-agent"
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": g}, "jira")
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), invokeReq("mcp:jira:create_issue"))
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Empty(t, f.connected)
}

// A member owns its bank, its run and its agent and nothing else. A request that
// names another mission is refused, whatever the grant holds, and it reaches no
// connector, no merge check and no flight recorder of another mission.
func TestMemberInvoke_ARequestThatNamesAnotherMissionIsRefused(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "ticket")}, "jira")
	for name, info := range map[string]*harnesspb.ContextInfo{
		"another mission": {MissionId: "mission-of-someone-else", MissionRunId: "run-1"},
		"another run":     {MissionId: "bank-1", MissionRunId: "run-of-someone-else"},
		"another agent":   {MissionId: "bank-1", MissionRunId: "run-1", AgentName: "zerocool"},
	} {
		req := invokeReq("mcp:jira:create_issue")
		req.Context = info
		resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), req)
		require.NoError(t, err, name)
		assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode(), name)
	}
	assert.Empty(t, f.connected)
	assert.Empty(t, f.captured)
}

// The mission and the run of a member call come from the verified grant. A call
// with no ContextInfo still runs, and the flight recorder holds it under the bank
// and the run of the member (ADR-0131).
func TestMemberInvoke_TheRecordUsesTheVerifiedContextAndASilentRequestStillRecords(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": grantOf("lg-1", "ticket")}, "jira")
	req := invokeReq("mcp:jira:create_issue")
	req.Context = nil
	resp, err := f.svc.CallToolProto(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), req)
	require.NoError(t, err)
	require.Nil(t, resp.GetError(), "%v", resp.GetError())
	require.Len(t, f.captured, 1, "the flight recorder must hold the call")
	assert.Equal(t, loopTenantA, f.captured[0].tenant)
	assert.Equal(t, "bank-1", f.captured[0].call.MissionID)
	assert.Equal(t, "run-1", f.captured[0].call.MissionRunID)
}

type memFindings struct {
	stored []agent.Finding
	tenant string
	err    error
}

func (m *memFindings) Store(_ context.Context, tenant string, _ types.ID, f agent.Finding) error {
	if m.err != nil {
		return m.err
	}
	m.tenant = tenant
	m.stored = append(m.stored, f)
	return nil
}

func (m *memFindings) Get(context.Context, string, types.ID, FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}

func submitReq() *harnesspb.SubmitFindingRequest {
	return &harnesspb.SubmitFindingRequest{
		Context: &harnesspb.ContextInfo{MissionId: "bank-1", MissionRunId: "run-1"},
		Finding: &typespb.Finding{
			Title: "open ticket queue", Severity: typespb.FindingSeverity_FINDING_SEVERITY_HIGH,
			AgentName: "someone-else",
		},
	}
}

func findingGrant() *LoopGrant {
	g := grantOf("lg-1", "ticket")
	g.HarnessCalls = []string{"SubmitFinding"}
	return g
}

func (f *loopFixture) withFindings() (*memFindings, *[]FindingRaised) {
	store := &memFindings{}
	var raised []FindingRaised
	WithMemberFindings(store, func(_ context.Context, r FindingRaised) { raised = append(raised, r) })(f.svc)
	return store, &raised
}

// A granted member submits a finding. The daemon stores it as the member: the
// tenant is the tenant of the verified grant, SubmittedBy is the member
// principal, and the agent name is the verified agent, not the payload.
func TestMemberSubmitFinding_AGrantedMemberStoresAFindingAsTheMember(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": findingGrant()})
	store, raised := f.withFindings()

	resp, err := f.svc.SubmitFinding(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), submitReq())
	require.NoError(t, err)
	require.Nil(t, resp.GetError(), "%v", resp.GetError())
	require.Len(t, store.stored, 1)
	got := store.stored[0]
	assert.Equal(t, loopTenantA, store.tenant)
	assert.Equal(t, loopTenantA, got.TenantID)
	assert.Equal(t, "member:member-1", got.SubmittedBy)
	assert.Equal(t, "intake-agent", got.AgentName, "the name of the payload must not win")
	// The stored row keeps the verified agent name: it rides on EnhancedFinding
	// and comes back on the base finding through the store read.
	back := findingFromStore(enhancedForStore(got, ""))
	assert.Equal(t, "intake-agent", back.AgentName)
	assert.Equal(t, "member:member-1", back.SubmittedBy)
	require.Len(t, *raised, 1)
	assert.Equal(t, "member:member-1", (*raised)[0].SubmittedBy)
	assert.Equal(t, "intake-agent", (*raised)[0].AgentName, "the name of the payload must not win")
	text := f.auditText()
	assert.Contains(t, text, `"result":"success"`)
	assert.Contains(t, text, `"loop_grant_id":"lg-1"`)
}

// The audit record shows an agent identity and not a person.
func TestMemberSubmitFinding_TheAuditActorIsNotAPerson(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": findingGrant()})
	f.withFindings()
	resp, err := f.svc.SubmitFinding(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), submitReq())
	require.NoError(t, err)
	require.Nil(t, resp.GetError())
	events := f.durable.Events()
	require.NotEmpty(t, events)
	for _, e := range events {
		assert.Equal(t, "member:member-1", e.ActorID)
		assert.NotEqual(t, "user", e.ActorType, "a member is not a person")
	}
}

// A member with no grant, a grant with no finding right, and a grant of another
// tenant are each refused. Nothing is stored.
func TestMemberSubmitFinding_UngrantedMembersAreRefused(t *testing.T) {
	for name, grants := range map[string]map[string]*LoopGrant{
		"no grant":                    nil,
		"a grant with no right":       {loopTenantA + "/member-1": grantOf("lg-1", "ticket")},
		"a grant of tenant B":         {"tenant-b/member-1": findingGrant()},
		"a grant of the other member": {loopTenantA + "/member-2": findingGrant()},
	} {
		f := newLoopFixture(t, grants)
		store, raised := f.withFindings()
		resp, err := f.svc.SubmitFinding(loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1"), submitReq())
		require.NoError(t, err, name)
		assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode(), name)
		assert.Empty(t, store.stored, name)
		assert.Empty(t, *raised, name)
	}
}

// A revoked grant stops the next finding at once. It does not wait for the
// renewal of the token.
func TestMemberSubmitFinding_ARevokedGrantStopsTheNextFinding(t *testing.T) {
	f := newLoopFixture(t, map[string]*LoopGrant{loopTenantA + "/member-1": findingGrant()})
	store, _ := f.withFindings()
	ctx := loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1")

	resp, err := f.svc.SubmitFinding(ctx, submitReq())
	require.NoError(t, err)
	require.Nil(t, resp.GetError())

	delete(f.source.grants, loopTenantA+"/member-1") // the admin revokes the grant
	resp, err = f.svc.SubmitFinding(ctx, submitReq())
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Len(t, store.stored, 1)
}

func TestMemberSubmitFinding_RefusalsAndOutages(t *testing.T) {
	ctx := loopMemberCtx(t, loopTenantA, "intake-agent", "bank-1", "member-1", "run-1")
	grants := map[string]*LoopGrant{loopTenantA + "/member-1": findingGrant()}

	f := newLoopFixture(t, grants)
	f.withFindings()
	req := submitReq()
	req.Context = &harnesspb.ContextInfo{MissionId: "mission-of-someone-else"}
	resp, err := f.svc.SubmitFinding(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode(), "another mission")

	f = newLoopFixture(t, grants)
	f.source.err = errors.New("tenant database down")
	f.withFindings()
	resp, err = f.svc.SubmitFinding(ctx, submitReq())
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode(), "grant store down")

	f = newLoopFixture(t, grants)
	resp, err = f.svc.SubmitFinding(ctx, submitReq())
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode(), "no finding store wired")

	f = newLoopFixture(t, grants)
	store, _ := f.withFindings()
	store.err = errors.New("db down")
	resp, err = f.svc.SubmitFinding(ctx, submitReq())
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode(), "finding store down")
	// A failed store gets a failure record and no success record.
	text := f.auditText()
	assert.Contains(t, text, `"result":"failure"`)
	assert.Contains(t, text, "store_failed")
	assert.NotContains(t, text, `"result":"success"`)

	f = newLoopFixture(t, grants)
	f.withFindings()
	f.svc.connectorAudit = nil
	resp, err = f.svc.SubmitFinding(ctx, submitReq())
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode(), "no finding without its audit record")

	f = newLoopFixture(t, grants)
	f.svc.members = loopFakeMembers{err: errors.New("bank store down")}
	resp, err = f.svc.SubmitFinding(ctx, submitReq())
	require.NoError(t, err)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, resp.GetError().GetCode(), "bank store down")
}

// A bank member call carries the run of its verified grant, and never a run that the
// request names. The link of a closed fix job binds the head of its merge request to
// this run, so the member call must carry it.
func TestMemberCall_ContextInfoCarriesTheRunOfTheGrant(t *testing.T) {
	m := memberCall{tenant: "acme", agent: "fix-agent", memberID: "member-1", bankID: "bank-1", runID: "run-1"}

	info := m.contextInfo()

	if info.GetMissionRunId() != "run-1" || info.GetMissionId() != "bank-1" || info.GetAgentName() != "fix-agent" {
		t.Errorf("context = %+v, want the run, the bank and the agent of the grant", info)
	}
}

// The tool call record carries the task of the verified task grant, and never the task that
// the request body names. For a turn of a bank member it is the id of the job, and the
// link of a closed job binds the head of its merge request to it.
func TestCaptureToolCall_CarriesTheTaskOfTheVerifiedGrant(t *testing.T) {
	var got []ToolCallRecord
	svc := &HarnessCallbackService{logger: slog.Default()}
	WithToolCallSink(func(_ context.Context, _ string, call ToolCallRecord) { got = append(got, call) })(svc)
	info := &harnesspb.ContextInfo{MissionId: "bank-1", MissionRunId: "member-run-1", TaskId: "job-forged"}

	withGrant := withTaskGrantClaims(testCtxWithTenant(), sdkcg.Claims{TaskID: "job-1"})
	svc.captureToolCall(withGrant, info, "tc1", "mcp:github-fixloop:open_merge_request", `{}`, `{}`, "")
	svc.captureToolCall(testCtxWithTenant(), info, "tc2", "mcp:github-fixloop:open_merge_request", `{}`, `{}`, "")

	if len(got) != 2 {
		t.Fatalf("recorded %d calls, want 2", len(got))
	}
	if got[0].GrantTaskID != "job-1" || got[0].MissionRunID != "member-run-1" {
		t.Errorf("with a grant: task %q run %q, want job-1 and the run of the member", got[0].GrantTaskID, got[0].MissionRunID)
	}
	if got[1].GrantTaskID != "" {
		t.Errorf("with no grant: task %q, want none: the task of the body must not count", got[1].GrantTaskID)
	}
}
