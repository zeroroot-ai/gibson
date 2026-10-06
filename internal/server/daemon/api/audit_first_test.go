// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

var errAuditDown = errors.New("audit store down")

// A state change whose audit record cannot be written does not happen, and
// the caller gets Unavailable (gibson#676).
func TestCreateAgentIdentity_NoRecordNoIdentity(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
		WithTenantAdminAuditWriter(&fakeAuditWriter{syncErr: errAuditDown})
	_, err := srv.CreateAgentIdentity(ctxWithTenantAdmin(context.Background(), "acme", "user-admin"),
		&tenantpb.CreateAgentIdentityRequest{Name: "my-agent", Kind: tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if len(fakeidp.deleteCalls) != 1 {
		t.Errorf("the service account was not rolled back: %d delete calls", len(fakeidp.deleteCalls))
	}
}

func TestRevokeAgentIdentity_NoRecordNoRevoke(t *testing.T) {
	fakeidp := &fakeIDPClient{}
	az := newFakeAuthorizer().allow("tenant:acme", "belongs_to", "agent_principal:some-uuid")
	srv := newTestDaemonServer(t).
		WithIdPAdminClient(fakeidp).
		WithAuthorizer(az).
		WithTenantAdminAuditWriter(&fakeAuditWriter{syncErr: errAuditDown})
	_, err := srv.RevokeAgentIdentity(ctxWithTenantAdmin(context.Background(), "acme", "user-admin"),
		&tenantpb.RevokeAgentIdentityRequest{PrincipalId: "agent_principal:some-uuid"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if len(fakeidp.deleteCalls) != 0 {
		t.Errorf("the identity was revoked with no record: %d delete calls", len(fakeidp.deleteCalls))
	}
}

func TestRewindMission_NoRecordNoRun(t *testing.T) {
	started := false
	srv := NewDaemonServer(&mockDaemon{
		rewindMissionFn: func(context.Context, RewindRequest) (string, error) {
			started = true
			return "m-2", nil
		},
	}, nil, nil)
	srv.WithTenantAdminAuditWriter(&fakeAuditWriter{syncErr: errAuditDown})
	_, err := srv.RewindMission(missionViewerCtx(), &daemonpb.RewindMissionRequest{MissionId: "m-1", CheckpointId: "scan"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v (%v), want Unavailable", status.Code(err), err)
	}
	if started {
		t.Error("a run started with no record")
	}
}
