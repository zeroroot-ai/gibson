// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// CreateMission stamps the caller as the creator and hands it back on the
// response (hosted#205). Only the id is recorded, never a name.
func TestCreateMission_StampsCaller(t *testing.T) {
	var got CreateMissionData
	daemon := &mockDaemon{
		createMissionFn: func(_ context.Context, req CreateMissionData) (CreateMissionResultData, error) {
			got = req
			return CreateMissionResultData{MissionID: "m1", Name: req.Name, TargetID: req.TargetID, MissionDefinitionID: req.MissionDefinitionID, CreatedBy: req.CreatedBy}, nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "123456789012345678")

	resp, err := server.CreateMission(ctx, &daemonpb.CreateMissionRequest{Name: "scan", TargetId: "t1", MissionDefinitionId: "d1"})
	if err != nil {
		t.Fatalf("CreateMission: %v", err)
	}
	want := principal.Principal{Kind: principal.User, ID: "123456789012345678"}
	if got.CreatedBy != want {
		t.Fatalf("daemon received creator %+v, want %+v", got.CreatedBy, want)
	}
	if got := resp.GetMission().GetMissionDefinitionId(); got != "d1" {
		t.Fatalf("response mission_definition_id = %q, want d1", got)
	}
	cb := resp.GetMission().GetCreatedBy()
	if cb.GetKind() != commonpb.Principal_KIND_USER || cb.GetId() != want.ID {
		t.Fatalf("response creator = %v, want user %s", cb, want.ID)
	}
}

// A request with no caller identity is refused before the daemon sees it:
// a mission must always name who created it.
func TestCreateMission_RefusesWithoutIdentity(t *testing.T) {
	called := false
	daemon := &mockDaemon{createMissionFn: func(context.Context, CreateMissionData) (CreateMissionResultData, error) {
		called = true
		return CreateMissionResultData{}, nil
	}}
	server := NewDaemonServer(daemon, nil, nil)

	_, err := server.CreateMission(context.Background(), &daemonpb.CreateMissionRequest{Name: "scan", TargetId: "t1", MissionDefinitionId: "d1"})
	if status_grpc.Code(err) != codes.Unauthenticated || called {
		t.Fatalf("got err=%v called=%v, want Unauthenticated and no daemon call", err, called)
	}
}

// ListMissions carries the creator to the wire, and a mission created before
// attribution existed carries none.
func TestListMissions_CarriesCreator(t *testing.T) {
	daemon := &mockDaemon{listMissionsFn: func(context.Context, bool, string, string, int, int) ([]MissionData, int, error) {
		return []MissionData{
			{ID: "m1", TenantID: "acme", Name: "new", CreatedBy: principal.Principal{Kind: principal.Component, ID: "agent_principal:acme/recon"}},
			{ID: "m0", TenantID: "acme", Name: "old"},
		}, 2, nil
	}}
	server := NewDaemonServer(daemon, nil, nil)
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "caller")

	resp, err := server.ListMissions(ctx, &daemonpb.ListMissionsRequest{})
	if err != nil {
		t.Fatalf("ListMissions: %v", err)
	}
	ms := resp.GetMissions()
	if len(ms) != 2 {
		t.Fatalf("got %d missions, want 2", len(ms))
	}
	if cb := ms[0].GetCreatedBy(); cb.GetKind() != commonpb.Principal_KIND_COMPONENT || cb.GetId() != "agent_principal:acme/recon" {
		t.Fatalf("m1 creator = %v, want the component", cb)
	}
	if ms[1].GetCreatedBy() != nil {
		t.Fatalf("m0 must carry no creator, got %v", ms[1].GetCreatedBy())
	}
}
