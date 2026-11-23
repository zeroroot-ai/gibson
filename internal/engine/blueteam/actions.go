// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package blueteam

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// The audit records that this read joins.
const (
	// actionToolCall is the record of one connector call of an agent
	// (internal/engine/metatool). Its metadata holds the result and the tool.
	actionToolCall = "connector.tool.call"
	// grantAdded and grantRemoved are the records of a change of a grant
	// (internal/server/admin/grants_admin.go). The actor is the person who gave
	// the grant, and the target is the principal of the agent.
	grantAdded   = "agent_grant_added"
	grantRemoved = "agent_grant_removed"
	// decisionAllow is the decision of an audit record of a grant change that took
	// effect. A record with another decision (deny) records a change that failed
	// after its record was written, so it never names a grantor.
	decisionAllow = "allow"
	// resultIntent is the record that comes before the call. Only the result
	// record counts as an action.
	resultIntent = "intent"
	resultFailed = "failure"
	// errUnauthorized is the error class of a call that the check refused.
	errUnauthorized = "unauthorized"
)

// executeTupleRelation is the relation that the grant admin writes for the action
// can_execute. can_execute is computed in the FGA model and takes no tuple, so
// the tuple is on direct_execute (internal/platform/authz.GrantTupleRelation).
var executeTupleRelation = mustExecuteRelation()

func mustExecuteRelation() string {
	r, ok := authz.GrantTupleRelation("can_execute")
	if !ok {
		panic("blueteam: the grant admin has no tuple relation for can_execute")
	}
	return r
}

// relationExecute is the action that lets an agent call a connector. A call is
// grouped under it, and the grant of it is the tuple on executeTupleRelation.
const relationExecute = "can_execute"

// Grant names a grant by its object and relation.
type Grant struct {
	Object   string
	Relation string
}

// ActionGroup is the set of agent actions that one grant allowed, given by one
// person. A refused action sits in its own group, with the grant that it lacked.
type ActionGroup struct {
	// Grant is the grant that allowed the action. For a refused action it is
	// the grant that the agent lacked.
	Grant Grant
	// Grantor is the actor of the record that gave the grant. It is empty when
	// the audit record holds no grant for the action, and for a refused action.
	Grantor string
	Refused bool
	Count   int
	First   time.Time
	Last    time.Time
	// Agents and Tools are the sorted ids that appear in the group.
	Agents []string
	Tools  []string
	// RecordIDs are the ids of the audit records of the actions of the group,
	// in the order of their time, so each row links to its own records.
	RecordIDs []string
}

type grantEvent struct {
	at      time.Time
	added   bool
	grantor string
}

// grantEvents indexes the grant changes of the execute relation by agent
// principal and by object.
func grantEvents(changes []audit.PgEntry) map[string]map[string][]grantEvent {
	byAgent := map[string]map[string][]grantEvent{} // principal -> object -> events
	for _, c := range changes {
		if (c.Action != grantAdded && c.Action != grantRemoved) || c.Decision != decisionAllow {
			continue
		}
		var md struct{ Object, Relation string }
		if json.Unmarshal(c.Metadata, &md) != nil || md.Relation != executeTupleRelation {
			continue
		}
		if byAgent[c.TargetID] == nil {
			byAgent[c.TargetID] = map[string][]grantEvent{}
		}
		byAgent[c.TargetID][md.Object] = append(byAgent[c.TargetID][md.Object],
			grantEvent{at: c.CreatedAt, added: c.Action == grantAdded, grantor: c.ActorID})
	}
	return byAgent
}

// callKey returns the group of one call record and its tool. ok is false for
// a record that is no result of a call.
func callKey(c audit.PgEntry, byAgent map[string]map[string][]grantEvent) (key groupKey, tool string, ok bool) {
	var md struct {
		Result  string
		Details struct{ Tool, Error string }
	}
	if json.Unmarshal(c.Metadata, &md) != nil || md.Result == resultIntent || md.Result == "" {
		return groupKey{}, "", false
	}
	grant := Grant{Object: authz.ConnectorComponentObject(c.TargetID), Relation: relationExecute}
	key = groupKey{grant: grant}
	if md.Result == resultFailed && md.Details.Error == errUnauthorized {
		key.refused = true
	} else {
		key.grantor = grantorAt(byAgent[c.ActorID][grant.Object], c.CreatedAt)
	}
	return key, md.Details.Tool, true
}

// add counts one call record in the group.
func (g *ActionGroup) add(c audit.PgEntry) {
	g.Count++
	if c.ID != "" {
		g.RecordIDs = append(g.RecordIDs, c.ID)
	}
	if c.CreatedAt.Before(g.First) {
		g.First = c.CreatedAt
	}
	if c.CreatedAt.After(g.Last) {
		g.Last = c.CreatedAt
	}
}

type groupKey struct {
	grant   Grant
	grantor string
	refused bool
}

// GroupActions groups the connector calls of the agents in [from, to] by the
// grant that allowed each one and by the person who gave that grant. calls and
// changes are audit records of one tenant. changes must reach back far enough to
// hold the grants that are still active, so the caller passes every change up
// to `to`.
func GroupActions(calls, changes []audit.PgEntry, from, to time.Time) []ActionGroup {
	byAgent := grantEvents(changes)
	groups := map[groupKey]*ActionGroup{}
	agents := map[groupKey]map[string]bool{}
	tools := map[groupKey]map[string]bool{}
	for _, c := range calls {
		if c.Action != actionToolCall || c.CreatedAt.Before(from) || c.CreatedAt.After(to) {
			continue
		}
		key, tool, ok := callKey(c, byAgent)
		if !ok {
			continue
		}
		g := groups[key]
		if g == nil {
			g = &ActionGroup{Grant: key.grant, Grantor: key.grantor, Refused: key.refused, First: c.CreatedAt}
			groups[key], agents[key], tools[key] = g, map[string]bool{}, map[string]bool{}
		}
		g.add(c)
		agents[key][c.ActorID] = true
		if tool != "" {
			tools[key][tool] = true
		}
	}

	out := make([]ActionGroup, 0, len(groups))
	for k, g := range groups {
		g.Agents, g.Tools = sortedKeys(agents[k]), sortedKeys(tools[k])
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Refused != b.Refused:
			return !a.Refused
		case a.Grant.Object != b.Grant.Object:
			return a.Grant.Object < b.Grant.Object
		default:
			return a.Grantor < b.Grantor
		}
	})
	return out
}

// grantorAt returns the person who gave the grant that was in force at t. The
// last change at or before t decides. A removal ends the grant, so no grantor
// is in force.
func grantorAt(events []grantEvent, t time.Time) string {
	if e, ok := grantEventAt(events, t); ok {
		return e.grantor
	}
	return ""
}

// grantEventAt returns the change that gave the grant in force at t. ok is false
// when no change is at or before t, and when the last one removed the grant.
func grantEventAt(events []grantEvent, t time.Time) (grantEvent, bool) {
	var last *grantEvent
	for i := range events {
		e := &events[i]
		if !e.at.After(t) && (last == nil || !e.at.Before(last.at)) {
			last = e
		}
	}
	if last == nil || !last.added {
		return grantEvent{}, false
	}
	return *last, true
}

// GrantorOf returns the person who gave principal the execute grant on object,
// in force at t, and the time of that change. changes are the audit records of
// agent_grant_added and agent_grant_removed. ok is false when no grant is in
// force at t, or when the records name none.
func GrantorOf(changes []audit.PgEntry, principal, object string, t time.Time) (grantor string, at time.Time, ok bool) {
	e, found := grantEventAt(grantEvents(changes)[principal][object], t)
	if !found {
		return "", time.Time{}, false
	}
	return e.grantor, e.at, true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
