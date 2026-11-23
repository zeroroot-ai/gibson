// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package blueteam

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// change builds the audit record that the grant admin writes for a change that
// took effect: the tuple relation is direct_execute (the grant admin writes the
// tuple relation of the action can_execute) and the decision is allow.
func change(action, actor, agent, connector string, when time.Time) audit.PgEntry {
	rel, _ := authz.GrantTupleRelation("can_execute")
	md, _ := json.Marshal(map[string]string{"object": authz.ConnectorComponentObject(connector), "relation": rel})
	return audit.PgEntry{
		Action: action, ActorID: actor, TargetType: "agent_grant", TargetID: agent, Decision: "allow",
		Metadata: md, CreatedAt: when,
	}
}

// failedChange is the record of a change that failed after its record was written.
func failedChange(action, actor, agent, connector string, when time.Time) audit.PgEntry {
	e := change(action, actor, agent, connector, when)
	e.Decision = "deny"
	return e
}

func call(agent, connector, tool, result, errClass string, when time.Time) audit.PgEntry {
	d := map[string]string{"tool": tool}
	if errClass != "" {
		d["error"] = errClass
	}
	md, _ := json.Marshal(map[string]any{"result": result, "details": d})
	return audit.PgEntry{Action: "connector.tool.call", ActorID: agent, TargetType: "connector", TargetID: connector, Metadata: md, CreatedAt: when}
}

func TestGroupActions_ByGrantAndGrantor(t *testing.T) {
	changes := []audit.PgEntry{
		change("agent_grant_added", "user:ann", "agent:a1", "gitlab", at(0)),
		change("agent_grant_added", "user:bob", "agent:a2", "gitlab", at(0)),
	}
	calls := []audit.PgEntry{
		call("agent:a1", "gitlab", "merge", "intent", "", at(1)),
		call("agent:a1", "gitlab", "merge", "success", "", at(1)),
		call("agent:a1", "gitlab", "open", "success", "", at(2)),
		call("agent:a2", "gitlab", "merge", "success", "", at(2)),
	}
	got := GroupActions(calls, changes, at(0), at(5))
	if len(got) != 2 {
		t.Fatalf("groups = %+v", got)
	}
	if got[0].Grantor != "user:ann" || got[0].Count != 2 || got[1].Grantor != "user:bob" || got[1].Count != 1 {
		t.Fatalf("groups = %+v", got)
	}
	if got[0].Grant.Relation != "can_execute" || got[0].Grant.Object != authz.ConnectorComponentObject("gitlab") {
		t.Fatalf("grant = %+v", got[0].Grant)
	}
}

func TestGroupActions_RefusedShowsTheGrantItLacked(t *testing.T) {
	calls := []audit.PgEntry{call("agent:a1", "gitlab", "merge", "failure", "unauthorized", at(1))}
	got := GroupActions(calls, nil, at(0), at(5))
	if len(got) != 1 || !got[0].Refused || got[0].Grantor != "" ||
		got[0].Grant.Object != authz.ConnectorComponentObject("gitlab") {
		t.Fatalf("groups = %+v", got)
	}
}

func TestGroupActions_RemovedGrantAndRange(t *testing.T) {
	changes := []audit.PgEntry{
		change("agent_grant_added", "user:ann", "agent:a1", "gitlab", at(0)),
		change("agent_grant_removed", "user:ann", "agent:a1", "gitlab", at(2)),
	}
	calls := []audit.PgEntry{
		call("agent:a1", "gitlab", "merge", "success", "", at(1)),
		call("agent:a1", "gitlab", "merge", "success", "", at(3)), // no grant in force
		call("agent:a1", "gitlab", "merge", "success", "", at(9)), // outside the range
	}
	got := GroupActions(calls, changes, at(0), at(5))
	if len(got) != 2 {
		t.Fatalf("groups = %+v", got)
	}
	var withGrantor, without int
	for _, g := range got {
		switch g.Grantor {
		case "user:ann":
			withGrantor += g.Count
		case "":
			without += g.Count
		}
	}
	if withGrantor != 1 || without != 1 {
		t.Fatalf("groups = %+v", got)
	}
}

// Each group lists the ids of the audit records of its actions, so a row of
// the dashboard links to its own records.
func TestGroupActions_NamesTheAuditRecordsOfEachGroup(t *testing.T) {
	from := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	call := func(id string, at time.Time) audit.PgEntry {
		return audit.PgEntry{
			ID: id, ActorID: "agent_principal:a1", Action: actionToolCall, TargetID: "okta", CreatedAt: at,
			Metadata: []byte(`{"Result":"success","Details":{"Tool":"suspend_user"}}`),
		}
	}
	groups := GroupActions([]audit.PgEntry{call("rec-1", from.Add(time.Hour)), call("rec-2", from.Add(2*time.Hour))}, nil, from, to)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if got := groups[0].RecordIDs; len(got) != 2 || got[0] != "rec-1" || got[1] != "rec-2" {
		t.Fatalf("record ids = %v", got)
	}
}

func TestGrantorOf(t *testing.T) {
	t0 := time.Unix(1000, 0)
	changes := []audit.PgEntry{
		change("agent_grant_added", "admin-1", "agent_principal:p1", "okta-response", t0),
		change("agent_grant_removed", "admin-1", "agent_principal:p1", "okta-response", t0.Add(time.Hour)),
		change("agent_grant_added", "admin-2", "agent_principal:p1", "okta-response", t0.Add(2*time.Hour)),
		change("agent_grant_added", "admin-3", "agent_principal:p2", "okta-response", t0),
	}
	obj := authz.ConnectorComponentObject("okta-response")
	tests := []struct {
		name      string
		principal string
		at        time.Time
		want      string
		wantOK    bool
	}{
		{"before any grant", "agent_principal:p1", t0.Add(-time.Second), "", false},
		{"first grant", "agent_principal:p1", t0.Add(time.Minute), "admin-1", true},
		{"after the removal", "agent_principal:p1", t0.Add(90 * time.Minute), "", false},
		{"second grant", "agent_principal:p1", t0.Add(3 * time.Hour), "admin-2", true},
		{"another principal", "agent_principal:p2", t0.Add(time.Minute), "admin-3", true},
		{"unknown principal", "agent_principal:p9", t0.Add(time.Minute), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := GrantorOf(changes, tt.principal, obj, tt.at)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("GrantorOf = %q, %v, want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// The grant admin writes direct_execute, so the record of a real grant names it.
func TestGrantorOf_ReadsTheRelationThatTheGrantAdminWrites(t *testing.T) {
	t0 := time.Unix(1000, 0)
	obj := authz.ConnectorComponentObject("okta-response")
	rel, _ := authz.GrantTupleRelation("can_execute")
	if rel != "direct_execute" {
		t.Fatalf("the tuple relation of can_execute is %q, want direct_execute", rel)
	}
	md, _ := json.Marshal(map[string]string{"object": obj, "relation": "direct_execute"})
	real := audit.PgEntry{Action: "agent_grant_added", ActorID: "admin-1", TargetID: "p1", Decision: "allow", Metadata: md, CreatedAt: t0}
	if got, _, ok := GrantorOf([]audit.PgEntry{real}, "p1", obj, t0.Add(time.Minute)); !ok || got != "admin-1" {
		t.Errorf("GrantorOf = %q, %v, want admin-1", got, ok)
	}
	// A record of the computed relation names no grant, because it takes no tuple.
	md, _ = json.Marshal(map[string]string{"object": obj, "relation": "can_execute"})
	computed := audit.PgEntry{Action: "agent_grant_added", ActorID: "admin-1", TargetID: "p1", Decision: "allow", Metadata: md, CreatedAt: t0}
	if _, _, ok := GrantorOf([]audit.PgEntry{computed}, "p1", obj, t0.Add(time.Minute)); ok {
		t.Error("a record of the computed relation named a grantor")
	}
}

// Only a record with an allow decision counts. A failed re-add must not name its
// actor, and a failed remove must not end a grant that is in force.
func TestGrantorOf_UsesOnlyAllowedChanges(t *testing.T) {
	t0 := time.Unix(1000, 0)
	obj := authz.ConnectorComponentObject("okta-response")
	changes := []audit.PgEntry{
		change("agent_grant_added", "admin-1", "p1", "okta-response", t0),
		failedChange("agent_grant_added", "admin-2", "p1", "okta-response", t0.Add(time.Hour)),
		failedChange("agent_grant_removed", "admin-3", "p1", "okta-response", t0.Add(2*time.Hour)),
	}
	got, _, ok := GrantorOf(changes, "p1", obj, t0.Add(3*time.Hour))
	if !ok || got != "admin-1" {
		t.Errorf("GrantorOf = %q, %v, want admin-1: the failed changes count for nothing", got, ok)
	}
}

// GroupActions names the grantor of a call from the records that production writes.
func TestGroupActions_NamesTheGrantorFromAllowedDirectExecuteRecords(t *testing.T) {
	t0 := time.Unix(1000, 0)
	changes := []audit.PgEntry{
		change("agent_grant_added", "admin-1", "p1", "okta-response", t0),
		failedChange("agent_grant_added", "admin-2", "p1", "okta-response", t0.Add(time.Hour)),
	}
	calls := []audit.PgEntry{call("p1", "okta-response", "suspend_user", "success", "", t0.Add(2*time.Hour))}
	groups := GroupActions(calls, changes, t0, t0.Add(3*time.Hour))
	if len(groups) != 1 || groups[0].Grantor != "admin-1" {
		t.Fatalf("groups = %+v, want one group with grantor admin-1", groups)
	}
}
