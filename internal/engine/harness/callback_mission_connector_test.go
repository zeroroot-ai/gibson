// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
)

type pendingGate struct{}

func (pendingGate) Acquire(context.Context, metatool.ApprovalRequest) (metatool.ApprovalState, string, error) {
	return metatool.ApprovalStatePending, "req-1", nil
}
func (pendingGate) MayMerge(context.Context, string, string) (bool, error) { return true, nil }

// missionConnectorSvc is a service with a live run of tenant acme, a connector
// that the tenant enabled, and the audit and flight recorder wired.
func missionConnectorSvc(t *testing.T, allow map[string]bool, blocked []string) (*HarnessCallbackService, *fakeSearchAuthz, *[]string, *audittest.Recorder) {
	t.Helper()
	var captured []capturedTool
	svc, _, _ := newStreamCaptureSvc(t, &captured, nil)
	authzer := &fakeSearchAuthz{allow: allow}
	svc.componentAuthorizer = authzer
	rec := &audittest.Recorder{}
	svc.connectorAudit = newConnectorAudit(t, rec)
	called := []string{}
	svc.connectors = fakeConnectors{result: map[string]any{"ok": true}, called: &called}
	svc.authzStore = fakeSearchAuthzStore{state: &RunAuthzState{RunID: "run-1", MissionID: "m1", TenantID: "acme", Status: "active"}}
	svc.missionBlockedTools = func(context.Context, string, string) ([]string, error) { return blocked, nil }
	return svc, authzer, &called, rec
}

// A TOOL node that the tenant granted calls the connector on the governed path:
// the can_execute check of the person who started the mission, the audit records,
// and the call with the run of the mission.
func TestCallConnectorForMission_AGrantedNodeCallsTheConnector(t *testing.T) {
	svc, authzer, called, rec := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	out, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "github-fixloop", "read_file", map[string]any{"path": "go.mod"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if m, ok := out.(map[string]any); !ok || m["ok"] != true {
		t.Fatalf("result = %#v", out)
	}
	if authzer.lastUser != "user:alice" || authzer.lastRelation != "can_execute" || authzer.lastObject != "component:connector/github-fixloop" {
		t.Errorf("%s was checked for %q on %q, want can_execute for the initiator", authzer.lastRelation, authzer.lastUser, authzer.lastObject)
	}
	if len(*called) != 1 || (*called)[0] != "acme/github-fixloop/read_file" {
		t.Errorf("connector calls = %v", *called)
	}
	if n := len(rec.Events()); n != 2 {
		t.Errorf("audit records = %d, want the intent and the result", n)
	}
}

// A node of a connector that the tenant did not enable has no grant, and the
// connector gets no call. The same for a tenant switch that is off.
func TestCallConnectorForMission_AnUngrantedNodeIsRefused(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{}, nil)
	_, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "github-fixloop", "read_file", nil)
	if !errors.Is(err, metatool.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// The connector of another tenant is refused. The run of acme is not a run of
// tenant other, so the policy of the run is refused before any grant check, and
// a tenant with no grant on the connector gets nothing either.
func TestCallConnectorForMission_AnotherTenantIsRefused(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	if _, err := svc.CallConnectorForMission(context.Background(), "other", "m1", "run-1", "work-1", "user:alice", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a run of acme called a connector as tenant other")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// The mission deny list applies, and a run that cannot be read refuses the call.
func TestCallConnectorForMission_TheMissionPolicyApplies(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, []string{"mcp:github-fixloop:read_file"})
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "github-fixloop", "read_file", nil); !errors.Is(err, metatool.ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	svc.authzStore = failingAuthzStore{}
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "github-fixloop", "other_tool", nil); err == nil {
		t.Fatal("a run with no readable policy must refuse")
	}
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "", "work-1", "user:alice", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a call with no run must refuse")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// A node never calls a merge tool or a daemon-only tool. The refusal comes from
// the handler, after the intent record, so it has its audit records and its
// flight recorder line.
func TestCallConnectorForMission_ARoleToolIsRefusedByTheHandler(t *testing.T) {
	svc, _, called, rec := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	var recorded []capturedTool
	svc.toolCallSink = func(_ context.Context, tn string, call ToolCallRecord) {
		recorded = append(recorded, capturedTool{tenant: tn, call: call})
	}
	for _, tool := range []string{"merge_merge_request", "revert_merge_request"} {
		before := len(rec.Events())
		_, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "github-fixloop", tool, map[string]any{"merge_request": "a/b#1"})
		if !errors.Is(err, metatool.ErrNodeRole) {
			t.Errorf("%s: err = %v, want ErrNodeRole", tool, err)
		}
		if got := len(rec.Events()) - before; got != 2 {
			t.Errorf("%s: audit records = %d, want the intent and the result", tool, got)
		}
	}
	if len(recorded) != 2 {
		t.Errorf("flight recorder lines = %d, want 2", len(recorded))
	}
	for _, r := range recorded {
		if r.call.WorkID != "work-1" {
			t.Errorf("the record names task %q, want the work item of the node", r.call.WorkID)
		}
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// The run must belong to the mission of the node.
func TestCallConnectorForMission_AnotherMissionIsRefused(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "other-mission", "run-1", "work-1", "user:alice", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a node of another mission used the run of m1")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// A tool with an approval mark still waits for a person. An entry with response
// actions marks each tool that its manifest does not name (fail closed).
func TestCallConnectorForMission_AMarkedToolWaitsForApproval(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/crowdstrike-response": true}, nil)
	svc.toolApproval = pendingGate{}
	_, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "crowdstrike-response", "a_tool_the_manifest_does_not_name", map[string]any{"host": "h1"})
	if !errors.Is(err, metatool.ErrApprovalPending) {
		t.Fatalf("err = %v, want ErrApprovalPending", err)
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call before the approval: %v", *called)
	}
}

// A deny list that cannot be read refuses the call, and a tenant id that is not
// valid refuses it before any check.
func TestCallConnectorForMission_ARefusedPolicyAndABadTenant(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	svc.missionBlockedTools = func(context.Context, string, string) ([]string, error) {
		return nil, errors.New("the definition is unreadable")
	}
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "github-fixloop", "read_file", nil); err == nil ||
		!strings.Contains(err.Error(), "mission policy") {
		t.Fatalf("err = %v, want a policy refusal", err)
	}
	svc.authzStore = fakeSearchAuthzStore{state: &RunAuthzState{RunID: "run-1", MissionID: "m1", TenantID: "bad tenant!", Status: "active"}}
	if _, err := svc.CallConnectorForMission(context.Background(), "bad tenant!", "m1", "run-1", "w", "user:alice", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a tenant id that is not valid must refuse")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// A TOOL node runs as the person who started the mission. A person with a team
// or user execute deny on the connector is refused, and a person with none
// passes. The deny is one the tenant relation does not see, so the node must not
// take the authority of the tenant.
func TestCallConnectorForMission_ADeniedInitiatorIsRefused(t *testing.T) {
	svc, authzer, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	authzer.denied = map[string]bool{"user:denied": true}

	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:denied", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a person with an execute deny called the connector through a node")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call of a denied person: %v", *called)
	}
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:allowed", "github-fixloop", "read_file", nil); err != nil {
		t.Fatalf("an allowed person: %v", err)
	}
	if len(*called) != 1 {
		t.Fatalf("connector calls = %v, want the one of the allowed person", *called)
	}
}

// A mission that no person started gives its node no authority.
func TestCallConnectorForMission_AMissionWithNoInitiatorIsRefused(t *testing.T) {
	svc, authzer, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	for _, initiator := range []string{"", "user:", "tenant:acme#member", "agent_principal:a1"} {
		if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", initiator, "github-fixloop", "read_file", nil); err == nil {
			t.Fatalf("initiator %q: a node with no person called the connector", initiator)
		}
	}
	if len(*called) != 0 || authzer.lastObject != "" {
		t.Fatalf("a refused node reached a check or the connector: %v %q", *called, authzer.lastObject)
	}
}

// A check that errors is no answer, and the node fails closed.
func TestCallConnectorForMission_ACheckErrorRefusesTheCall(t *testing.T) {
	svc, authzer, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	authzer.err = errors.New("fga down")
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "work-1", "user:alice", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a check error must refuse the call")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// The read that the daemon makes for itself, such as the alerts of a scan, asks
// the tenant. The kill switch of the tenant, a check error and a tenant with no
// grant stop it, and the mission policy still applies.
func TestCallConnectorForMissionAsTenant(t *testing.T) {
	svc, authzer, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	if _, err := svc.CallConnectorForMissionAsTenant(context.Background(), "acme", "m1", "run-1", "work-1", "github-fixloop", "list_dependency_alerts", nil); err != nil {
		t.Fatalf("call: %v", err)
	}
	if authzer.lastUser != "tenant:acme" || authzer.lastRelation != "tenant_can_execute" || authzer.lastObject != "component:connector/github-fixloop" {
		t.Fatalf("%s was checked for %q on %q, want tenant_can_execute for the tenant", authzer.lastRelation, authzer.lastUser, authzer.lastObject)
	}
	authzer.killed = map[string]bool{"component:connector/github-fixloop": true}
	if _, err := svc.CallConnectorForMissionAsTenant(context.Background(), "acme", "m1", "run-1", "work-1", "github-fixloop", "list_dependency_alerts", nil); err == nil {
		t.Fatal("a connector with its kill switch on must refuse")
	}
	authzer.killed = nil
	authzer.err = errors.New("fga down")
	if _, err := svc.CallConnectorForMissionAsTenant(context.Background(), "acme", "m1", "run-1", "work-1", "github-fixloop", "list_dependency_alerts", nil); err == nil {
		t.Fatal("a check error must refuse")
	}
	if len(*called) != 1 {
		t.Fatalf("connector calls = %v, want the first only", *called)
	}
}
