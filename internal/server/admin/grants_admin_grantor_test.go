// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/blueteam"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// asEntries turns the events that the writer builds into the rows that the audit
// read returns, one second apart from t.
func asEntries(evs []audit.Event, t time.Time) []audit.PgEntry {
	out := make([]audit.PgEntry, 0, len(evs))
	for i, e := range evs {
		out = append(out, audit.PgEntry{
			TenantID: e.TenantID, ActorID: e.ActorID, ActorType: e.ActorType, Action: e.Action,
			TargetType: e.TargetType, TargetID: e.TargetID, Decision: e.Decision, Metadata: e.Metadata,
			CreatedAt: t.Add(time.Duration(i) * time.Second),
		})
	}
	return out
}

// The grantor read of the incident report and of the blue team reads the records
// that this writer builds. The fixture is the output of grantAuditEvents, so a
// change in the relation, the decision or the keys of the writer fails this test.
func TestGrantAuditEvents_TheGrantorReadFindsTheGrantorOfWhatTheWriterBuilds(t *testing.T) {
	const principal = "agent_principal:p1"
	object := authz.ConnectorComponentObject("okta-response")
	tuples := GrantTuples(principal, []*tenantv1.GrantTuple{{Object: object, Relation: "can_execute"}})
	t0 := time.Unix(1000, 0)

	added := asEntries(GrantAuditEvents("user:admin-1", "acme", principal, "agent_grant_added", "allow", tuples), t0)
	got, _, ok := blueteam.GrantorOf(added, principal, object, t0.Add(time.Hour))
	if !ok || got != "user:admin-1" {
		t.Fatalf("GrantorOf = %q, %v, want user:admin-1 from the record of the writer", got, ok)
	}

	// The write failed after the allow record. The writer adds a deny record and the
	// allow stays, so the failed re-add names no grantor and the first grant stays.
	retry := append(asEntries(GrantAuditEvents("user:admin-2", "acme", principal, "agent_grant_added", "allow", tuples), t0.Add(time.Hour)),
		asEntries(GrantAuditEvents("user:admin-2", "acme", principal, "agent_grant_added", "deny", tuples), t0.Add(time.Hour+time.Second))...)
	got, _, ok = blueteam.GrantorOf(append(added, retry...), principal, object, t0.Add(2*time.Hour))
	if !ok || got != "user:admin-1" {
		t.Errorf("GrantorOf = %q, %v, want user:admin-1: the failed re-add of admin-2 did not take effect", got, ok)
	}

	// A failed delete leaves the grant in force.
	del := append(asEntries(GrantAuditEvents("user:admin-3", "acme", principal, "agent_grant_removed", "allow", tuples), t0.Add(time.Hour)),
		asEntries(GrantAuditEvents("user:admin-3", "acme", principal, "agent_grant_removed", "deny", tuples), t0.Add(time.Hour+time.Second))...)
	got, _, ok = blueteam.GrantorOf(append(added, del...), principal, object, t0.Add(2*time.Hour))
	if !ok || got != "user:admin-1" {
		t.Errorf("GrantorOf = %q, %v, want user:admin-1: the failed delete did not end the grant", got, ok)
	}
}
