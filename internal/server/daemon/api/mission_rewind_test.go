// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const testViewerSubject = "u-viewer"

// missionViewerCtx returns a context carrying an authenticated identity for
// tenant "acme".
func missionViewerCtx() context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{
		Subject: testViewerSubject,
		Tenant:  auth.MustNewTenantID("acme"),
	})
}

// A resume continues the same run. A request that names a checkpoint asks for
// a rewind, and the resume path refuses it rather than ignore the field.
func TestResumeMission_RefusesACheckpoint(t *testing.T) {
	resumed := false
	srv := NewDaemonServer(&mockDaemon{
		resumeMissionFn: func(context.Context, string) error { resumed = true; return nil },
	}, nil, nil)

	for _, req := range []*daemonpb.ResumeMissionRequest{
		{MissionId: "m-1", CheckpointId: "scan"},
		{MissionId: "m-1", TargetCheckpointId: "scan"},
	} {
		stream := &fakeStream[daemonpb.ResumeMissionResponse]{ctx: missionViewerCtx()}
		err := srv.ResumeMission(req, stream)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("resume with a checkpoint: code = %v (%v), want InvalidArgument", status.Code(err), err)
		}
	}
	if resumed {
		t.Fatal("the daemon resumed a run for a request that named a checkpoint")
	}
}

func TestGetMissionCheckpoints_MapsTheNodeEnds(t *testing.T) {
	srv := NewDaemonServer(&mockDaemon{
		getMissionCheckpointsFn: func(_ context.Context, id string) ([]MissionCheckpoint, error) {
			if id != "m-1" {
				t.Fatalf("mission id = %q", id)
			}
			return []MissionCheckpoint{
				{CheckpointID: "recon", NodeID: "recon", TimelinePosition: 4},
				{CheckpointID: "exploit", NodeID: "exploit", TimelinePosition: 9, SnapshotID: "snap-1"},
			}, nil
		},
	}, nil, nil)

	resp, err := srv.GetMissionCheckpoints(missionViewerCtx(), &daemonpb.GetMissionCheckpointsRequest{MissionId: "m-1"})
	if err != nil {
		t.Fatalf("GetMissionCheckpoints: %v", err)
	}
	cps := resp.GetCheckpoints()
	if len(cps) != 2 {
		t.Fatalf("got %d checkpoints, want 2", len(cps))
	}
	if cps[0].GetNodeId() != "recon" || cps[0].GetTimelinePosition() != 4 || cps[0].SnapshotId != nil {
		t.Errorf("first checkpoint = %v", cps[0])
	}
	if cps[1].GetSnapshotId() != "snap-1" {
		t.Errorf("second checkpoint snapshot = %q, want snap-1", cps[1].GetSnapshotId())
	}
}

func TestGetMissionCheckpoints_RequiresAMissionID(t *testing.T) {
	srv := NewDaemonServer(&mockDaemon{}, nil, nil)
	_, err := srv.GetMissionCheckpoints(missionViewerCtx(), &daemonpb.GetMissionCheckpointsRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestRewindMission_PassesTheRequestAndAudits(t *testing.T) {
	var got RewindRequest
	srv := NewDaemonServer(&mockDaemon{
		rewindMissionFn: func(_ context.Context, req RewindRequest) (string, error) {
			got = req
			return "m-2", nil
		},
	}, nil, nil)
	aw := newFakeAuditWriter()
	srv.WithTenantAdminAuditWriter(aw)

	instr := "try the second port"
	resp, err := srv.RewindMission(missionViewerCtx(), &daemonpb.RewindMissionRequest{
		MissionId:      "m-1",
		CheckpointId:   "scan",
		Instruction:    &instr,
		IdempotencyKey: "k-1",
	})
	if err != nil {
		t.Fatalf("RewindMission: %v", err)
	}
	if resp.GetMissionId() != "m-2" {
		t.Fatalf("mission id = %q, want the new run", resp.GetMissionId())
	}
	if got.MissionID != "m-1" || got.CheckpointID != "scan" || got.IdempotencyKey != "k-1" ||
		got.Instruction == nil || *got.Instruction != instr {
		t.Fatalf("daemon request = %+v", got)
	}
	evs := aw.recorded()
	if len(evs) != 1 || evs[0].Action != "mission.rewound" || evs[0].TargetID != "m-2" {
		t.Fatalf("audit = %+v, want one mission.rewound event for m-2", evs)
	}
}

func TestRewindMission_KeepsTheStatusOfTheDaemon(t *testing.T) {
	srv := NewDaemonServer(&mockDaemon{
		rewindMissionFn: func(context.Context, RewindRequest) (string, error) {
			return "", status.Error(codes.NotFound, "checkpoint scan not found")
		},
	}, nil, nil)
	_, err := srv.RewindMission(missionViewerCtx(), &daemonpb.RewindMissionRequest{MissionId: "m-1", CheckpointId: "scan"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

func TestRewindMission_RefusesAnIncompleteRequest(t *testing.T) {
	srv := NewDaemonServer(&mockDaemon{}, nil, nil)
	empty := ""
	for _, req := range []*daemonpb.RewindMissionRequest{
		{CheckpointId: "scan"},
		{MissionId: "m-1"},
		{MissionId: "m-1", CheckpointId: "scan", Instruction: &empty},
	} {
		_, err := srv.RewindMission(missionViewerCtx(), req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("request %v: code = %v, want InvalidArgument", req, status.Code(err))
		}
	}
}
