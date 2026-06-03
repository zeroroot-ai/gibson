// Package api — mission_graph_test.go unit tests for the MissionGraph + layout
// RPCs (request validation + nil-pool behavior). The projection and layout
// store internals are covered by internal/mission/graph and internal/mission.
//
// Spec: MissionGraph epic (sdk#278, gibson#598).
package api

import (
	"context"
	"testing"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

func TestGetMissionGraph_EmptyID_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := &DaemonServer{}
	_, err := srv.GetMissionGraph(context.Background(), &daemonpb.GetMissionGraphRequest{})
	if err == nil {
		t.Fatal("expected error for empty mission_definition_id")
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

func TestGetMissionGraph_NilPool_Unavailable(t *testing.T) {
	t.Parallel()
	srv := &DaemonServer{}
	_, err := srv.GetMissionGraph(context.Background(),
		&daemonpb.GetMissionGraphRequest{MissionDefinitionId: "def-1"})
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
	assertGRPCStatusCode(t, err, "Unavailable")
}

func TestGetMissionLayout_EmptyID_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := &DaemonServer{}
	_, err := srv.GetMissionLayout(context.Background(), &daemonpb.GetMissionLayoutRequest{})
	if err == nil {
		t.Fatal("expected error for empty mission_definition_id")
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

func TestSaveMissionLayout_MissingID_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := &DaemonServer{}

	// nil layout
	if _, err := srv.SaveMissionLayout(context.Background(), &daemonpb.SaveMissionLayoutRequest{}); err == nil {
		t.Fatal("expected error for nil layout")
	} else {
		assertGRPCStatusCode(t, err, "InvalidArgument")
	}

	// layout without mission_definition_id
	_, err := srv.SaveMissionLayout(context.Background(), &daemonpb.SaveMissionLayoutRequest{
		Layout: &daemonpb.MissionLayout{},
	})
	if err == nil {
		t.Fatal("expected error for missing mission_definition_id")
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

func TestSaveMissionLayout_NilPool_Unavailable(t *testing.T) {
	t.Parallel()
	srv := &DaemonServer{}
	_, err := srv.SaveMissionLayout(context.Background(), &daemonpb.SaveMissionLayoutRequest{
		Layout: &daemonpb.MissionLayout{MissionDefinitionId: "def-1"},
	})
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
	assertGRPCStatusCode(t, err, "Unavailable")
}
