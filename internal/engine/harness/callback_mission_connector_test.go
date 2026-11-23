// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
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
// the can_execute check of the member set of the tenant, the audit records, and
// the call with the run of the mission.
func TestCallConnectorForMission_AGrantedNodeCallsTheConnector(t *testing.T) {
	svc, authzer, called, rec := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	out, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "github-fixloop", "read_file", map[string]any{"path": "go.mod"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if m, ok := out.(map[string]any); !ok || m["ok"] != true {
		t.Fatalf("result = %#v", out)
	}
	if authzer.lastUser != "tenant:acme#member" || authzer.lastObject != "component:connector/github-fixloop" {
		t.Errorf("can_execute was checked for %q on %q", authzer.lastUser, authzer.lastObject)
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
	_, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "github-fixloop", "read_file", nil)
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
	if _, err := svc.CallConnectorForMission(context.Background(), "other", "m1", "run-1", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a run of acme called a connector as tenant other")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// The mission deny list applies, and a run that cannot be read refuses the call.
func TestCallConnectorForMission_TheMissionPolicyApplies(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, []string{"mcp:github-fixloop:read_file"})
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "github-fixloop", "read_file", nil); !errors.Is(err, metatool.ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	svc.authzStore = failingAuthzStore{}
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "github-fixloop", "other_tool", nil); err == nil {
		t.Fatal("a run with no readable policy must refuse")
	}
	if _, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "", "github-fixloop", "read_file", nil); err == nil {
		t.Fatal("a call with no run must refuse")
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call: %v", *called)
	}
}

// A node never calls a merge tool or a daemon-only tool.
func TestCallConnectorForMission_ARoleToolIsRefused(t *testing.T) {
	svc, _, called, _ := missionConnectorSvc(t, map[string]bool{"component:connector/github-fixloop": true}, nil)
	for _, tool := range []string{"merge_merge_request", "revert_merge_request"} {
		_, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "github-fixloop", tool, map[string]any{"merge_request": "a/b#1"})
		if !errors.Is(err, ErrMissionNodeRole) {
			t.Errorf("%s: err = %v, want ErrMissionNodeRole", tool, err)
		}
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
	_, err := svc.CallConnectorForMission(context.Background(), "acme", "m1", "run-1", "crowdstrike-response", "a_tool_the_manifest_does_not_name", map[string]any{"host": "h1"})
	if !errors.Is(err, metatool.ErrApprovalPending) {
		t.Fatalf("err = %v, want ErrApprovalPending", err)
	}
	if len(*called) != 0 {
		t.Fatalf("the connector got a call before the approval: %v", *called)
	}
}
