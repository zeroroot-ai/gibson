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
		if g.Grantor == "user:ann" {
			withGrantor += g.Count
		} else if g.Grantor == "" {
			without += g.Count
		}
	}
	if withGrantor != 1 || without != 1 {
		t.Fatalf("groups = %+v", got)
	}
}
