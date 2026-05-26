// Package api — update_mission_definition_test.go unit tests for
// DaemonService.UpdateMissionDefinition.
//
// Spec: gibson#437.
package api

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/mission"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestUpdateMissionDefinition_RejectsNilDefinition verifies that a request
// with a nil definition field returns codes.InvalidArgument.
func TestUpdateMissionDefinition_RejectsNilDefinition(t *testing.T) {
	t.Parallel()
	server := NewDaemonServer(&mockDaemon{}, nil, nil)
	_, err := server.UpdateMissionDefinition(context.Background(), &daemonpb.UpdateMissionDefinitionRequest{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", st.Code())
	}
}

// TestUpdateMissionDefinition_RejectsMissingName verifies that a definition
// without a name returns codes.InvalidArgument.
func TestUpdateMissionDefinition_RejectsMissingName(t *testing.T) {
	t.Parallel()
	server := NewDaemonServer(&mockDaemon{}, nil, nil)
	_, err := server.UpdateMissionDefinition(context.Background(), &daemonpb.UpdateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", st.Code())
	}
}

// TestUpdateMissionDefinition_NotFound verifies that a NOT_FOUND sentinel from
// the daemon is mapped to codes.NotFound on the wire.
func TestUpdateMissionDefinition_NotFound(t *testing.T) {
	t.Parallel()
	daemon := &mockDaemon{
		updateMissionDefinitionFn: func(_ context.Context, _ UpdateMissionDefinitionData) (UpdateMissionDefinitionResultData, error) {
			return UpdateMissionDefinitionResultData{}, mission.ErrDefinitionNotFound
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	_, err := server.UpdateMissionDefinition(context.Background(), &daemonpb.UpdateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{Name: "no-such-def"},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got %v (err=%v)", st.Code(), err)
	}
}

// TestUpdateMissionDefinition_HappyPath verifies that a successful update returns
// the stable server-assigned ID and maps to codes.OK.
func TestUpdateMissionDefinition_HappyPath(t *testing.T) {
	t.Parallel()
	const stableID = "01GY-STABLE-ID"

	daemon := &mockDaemon{
		updateMissionDefinitionFn: func(_ context.Context, req UpdateMissionDefinitionData) (UpdateMissionDefinitionResultData, error) {
			if req.Definition == nil {
				t.Fatal("expected non-nil definition in daemon call")
			}
			if req.Definition.GetName() != "my-def" {
				t.Fatalf("expected name my-def, got %q", req.Definition.GetName())
			}
			return UpdateMissionDefinitionResultData{MissionDefinitionID: stableID}, nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)

	resp, err := server.UpdateMissionDefinition(context.Background(), &daemonpb.UpdateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{
			Name:        "my-def",
			Version:     "2.0.0",
			Description: "updated description",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetMissionDefinitionId() != stableID {
		t.Fatalf("expected mission_definition_id %q, got %q", stableID, resp.GetMissionDefinitionId())
	}
}

// TestUpdateMissionDefinition_InternalError verifies that an unexpected daemon
// error is mapped to codes.Internal.
func TestUpdateMissionDefinition_InternalError(t *testing.T) {
	t.Parallel()
	daemon := &mockDaemon{
		updateMissionDefinitionFn: func(_ context.Context, _ UpdateMissionDefinitionData) (UpdateMissionDefinitionResultData, error) {
			return UpdateMissionDefinitionResultData{}, errors.New("redis connection refused")
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	_, err := server.UpdateMissionDefinition(context.Background(), &daemonpb.UpdateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{Name: "my-def"},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Fatalf("expected Internal, got %v (err=%v)", st.Code(), err)
	}
}
