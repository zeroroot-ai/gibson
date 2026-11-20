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

func change(action, actor, agent, connector string, when time.Time) audit.PgEntry {
	md, _ := json.Marshal(map[string]string{"object": authz.ConnectorComponentObject(connector), "relation": "can_execute"})
	return audit.PgEntry{Action: action, ActorID: actor, TargetType: "agent_grant", TargetID: agent, Metadata: md, CreatedAt: when}
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
