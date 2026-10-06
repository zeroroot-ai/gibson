// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
)

// TestAuditEntriesToResponse_NamesTheActorAndTheTarget: each audit event of
// ListAuditEvents names who acted, the class of the actor, and what the
// action changed (gibson#544, lane 11 row G23).
func TestAuditEntriesToResponse_NamesTheActorAndTheTarget(t *testing.T) {
	s := &DaemonServer{}
	ts := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	resp := s.auditEntriesToResponse([]audit.AuditEntry{
		{ID: "e1", Timestamp: ts, TenantID: "acme", ActorID: "user-1", ActorSource: "user",
			ActorEmail: "user-1", Action: "apikey.revoke", Resource: "apikey", ResourceID: "key-9"},
		{ID: "e2", Timestamp: ts, TenantID: "acme", ActorID: "svc-1", ActorSource: "system",
			Action: "tenant.quota", Resource: "tenant"},
		{ID: "e3", Timestamp: ts, TenantID: "acme", ActorID: "svc-1", ActorSource: "system",
			Action: "x", ResourceID: "only-id"},
	}, "next")

	require.Equal(t, "next", resp.GetNextCursor())
	require.Len(t, resp.GetEvents(), 3)
	ev := resp.GetEvents()[0]
	require.Equal(t, "user-1", ev.GetActorId())
	require.Equal(t, "user", ev.GetActorSource())
	require.Equal(t, "apikey:key-9", ev.GetTargetObject())
	require.Equal(t, "e1", ev.GetTraceId())
	require.Equal(t, "tenant", resp.GetEvents()[1].GetTargetObject())
	require.Equal(t, "system", resp.GetEvents()[1].GetActorSource())
	require.Equal(t, "only-id", resp.GetEvents()[2].GetTargetObject())
}
