// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	"github.com/zeroroot-ai/gibson/internal/platform/identity"
	identitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

var errGrantAuditDown = errors.New("audit store down")

// refusingWriter is a durable audit writer that refuses each write.
type refusingWriter struct{}

func (refusingWriter) Log(audit.Event)                              {}
func (refusingWriter) WriteSync(context.Context, audit.Event) error { return errGrantAuditDown }

func grantAuditServer(t *testing.T, az *stubAuthorizer, w audit.DurableWriter) *GrantsAdminServer {
	t.Helper()
	srv, err := NewGrantsAdminServer(GrantsAdminConfig{
		Reader:     noopReader{},
		Authorizer: az,
		Lookup: &stubLookup{records: map[string]identity.PrincipalRecord{
			"agent_principal:abc": {PrincipalID: "agent_principal:abc", TenantID: "zeroroot-ai", Kind: identitypb.PrincipalKind_PRINCIPAL_KIND_AGENT},
		}},
		AuditWriter: w,
	})
	if err != nil {
		t.Fatalf("NewGrantsAdminServer: %v", err)
	}
	return srv
}

func callerMayRead() *stubAuthorizer {
	return &stubAuthorizer{present: map[string]bool{
		"user:" + adminCallerSubject + "|can_read|component:gitlab": true,
	}}
}

var readGrant = []*tenantv1.GrantTuple{{Object: "component:gitlab", Relation: "can_read"}}

// A grant change writes its record first. With no durable record nothing
// changes, and a failed change gets a deny record (gibson#676).
func TestGrantChanges_WriteTheirRecordFirst(t *testing.T) {
	ctx := adminCtx(t, "zeroroot-ai")

	rec := &audittest.Recorder{}
	az := callerMayRead()
	srv := grantAuditServer(t, az, rec)
	if _, err := srv.WriteAgentGrants(ctx, &tenantv1.WriteAgentGrantsRequest{TargetPrincipalId: "agent_principal:abc", Grants: readGrant}); err != nil {
		t.Fatalf("WriteAgentGrants: %v", err)
	}
	if evs := rec.Events(); len(evs) != 1 || evs[0].Action != "agent_grant_added" || evs[0].ActorID != adminCallerSubject {
		t.Fatalf("records = %+v", evs)
	}

	down := callerMayRead()
	srv = grantAuditServer(t, down, refusingWriter{})
	_, err := srv.WriteAgentGrants(ctx, &tenantv1.WriteAgentGrantsRequest{TargetPrincipalId: "agent_principal:abc", Grants: readGrant})
	if status.Code(err) != codes.Unavailable || len(down.wrote) != 0 {
		t.Fatalf("no record: code %v, wrote %v; want Unavailable and nothing written", status.Code(err), down.wrote)
	}

	failing := callerMayRead()
	failing.writeErr = errGrantAuditDown
	rec = &audittest.Recorder{}
	srv = grantAuditServer(t, failing, rec)
	if _, err := srv.WriteAgentGrants(ctx, &tenantv1.WriteAgentGrantsRequest{TargetPrincipalId: "agent_principal:abc", Grants: readGrant}); err == nil {
		t.Fatal("a failed write succeeded")
	}
	evs := rec.Events()
	if len(evs) != 2 || evs[1].Decision != "deny" {
		t.Fatalf("records = %+v, want allow then deny", evs)
	}
}

// A delete with no durable record changes nothing.
func TestDeleteAgentGrants_NoRecordNoDelete(t *testing.T) {
	az := callerMayRead()
	az.present["agent_principal:abc|direct_read|component:gitlab"] = true
	srv := grantAuditServer(t, az, refusingWriter{})
	_, err := srv.DeleteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.DeleteAgentGrantsRequest{TargetPrincipalId: "agent_principal:abc", Grants: readGrant})
	if status.Code(err) != codes.Unavailable || len(az.deleted) != 0 {
		t.Fatalf("code %v, deleted %v; want Unavailable and nothing deleted", status.Code(err), az.deleted)
	}

	az.writeErr = errGrantAuditDown
	rec := &audittest.Recorder{}
	srv = grantAuditServer(t, az, rec)
	if _, err := srv.DeleteAgentGrants(adminCtx(t, "zeroroot-ai"), &tenantv1.DeleteAgentGrantsRequest{TargetPrincipalId: "agent_principal:abc", Grants: readGrant}); err == nil {
		t.Fatal("a failed delete succeeded")
	}
	if evs := rec.Events(); len(evs) != 2 || evs[1].Decision != "deny" {
		t.Fatalf("records = %+v, want allow then deny", evs)
	}
}
