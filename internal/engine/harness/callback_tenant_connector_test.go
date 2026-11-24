// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
)

// A connector call of the daemon for a tenant, such as the revert of a fix,
// takes the governed path (gibson#1465): the can_execute check of the tenant
// grant on the connector, the audit records with the grant as the actor, and
// the flight recorder record with the mission of the fix.
func TestCallConnectorForTenant_TakesTheGovernedPath(t *testing.T) {
	var captured []capturedTool
	svc, _, _ := newStreamCaptureSvc(t, &captured, nil)
	authzer := &fakeSearchAuthz{allow: map[string]bool{"component:connector/gitlab": true}}
	svc.componentAuthorizer = authzer
	rec := &audittest.Recorder{}
	svc.connectorAudit = newConnectorAudit(t, rec)
	var called []string
	svc.connectors = fakeConnectors{result: map[string]any{"merged": true}, called: &called}

	out, err := svc.CallConnectorForTenant(context.Background(), "acme", "fix-run-1", "gitlab",
		"revert_merge_request", map[string]any{"merge_request": "g/p!12"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if m, ok := out.(map[string]any); !ok || m["merged"] != true {
		t.Fatalf("result = %#v", out)
	}
	if authzer.tenantUser != "tenant:acme" || authzer.lastObject != "component:connector/gitlab" {
		t.Fatalf("can_execute was checked for %q on %q", authzer.tenantUser, authzer.lastObject)
	}
	if len(called) != 1 || called[0] != "acme/gitlab/revert_merge_request" {
		t.Fatalf("connector calls = %v", called)
	}
	if len(captured) != 1 || captured[0].tenant != "acme" {
		t.Fatalf("flight recorder records = %+v", captured)
	}
	events := rec.Events()
	if len(events) != 2 {
		t.Fatalf("audit records = %d, want the intent and the result", len(events))
	}
	for _, ev := range events {
		if ev.ActorID != "tenant:acme#member" || ev.TenantID != "acme" {
			t.Fatalf("audit record = %+v, want the grant of the tenant as the actor", ev)
		}
		if !strings.Contains(string(ev.Metadata), "fix-run-1") {
			t.Fatalf("audit record %s has no mission", ev.Metadata)
		}
	}

	// A tenant with no grant on the connector gets no call.
	authzer.allow = map[string]bool{}
	if _, err := svc.CallConnectorForTenant(context.Background(), "acme", "fix-run-1", "gitlab",
		"revert_merge_request", map[string]any{"merge_request": "g/p!12"}); err == nil {
		t.Fatal("a call with no grant must fail")
	}
	if len(called) != 1 {
		t.Fatalf("the connector got a call with no grant: %v", called)
	}
	// The tenant enabled the connector and then switched its execute off. The
	// call of the daemon stops with it.
	authzer.allow = map[string]bool{"component:connector/gitlab": true}
	authzer.killed = map[string]bool{"component:connector/gitlab": true}
	if _, err := svc.CallConnectorForTenant(context.Background(), "acme", "fix-run-1", "gitlab",
		"revert_merge_request", map[string]any{"merge_request": "g/p!12"}); err == nil {
		t.Fatal("a call of a connector with its kill switch on must fail")
	}
	if len(called) != 1 {
		t.Fatalf("the connector got a call with its kill switch on: %v", called)
	}
	if _, err := svc.CallConnectorForTenant(context.Background(), "", "m", "c", "t", nil); err == nil ||
		!strings.Contains(err.Error(), "tenant") {
		t.Fatalf("a call with no tenant: %v", err)
	}
}

// search_tools names the tool class of a connector tool, from the catalog
// (ADR-0177). A tool that no catalog connector serves has none.
func TestConnectorToolClass_ComesFromTheCatalog(t *testing.T) {
	if got := connectorToolClass("gitlab"); got != "git-host" {
		t.Errorf("gitlab = %q, want git-host", got)
	}
	if got := connectorToolClass("no-such-connector"); got != "" {
		t.Errorf("an unknown connector = %q, want empty", got)
	}
	if got := connectorToolClass(""); got != "" {
		t.Errorf("no connector = %q, want empty", got)
	}
}
