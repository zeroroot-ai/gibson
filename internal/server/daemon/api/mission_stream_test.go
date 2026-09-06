// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeStream is a minimal grpc.ServerStreamingServer for the mission RPCs.
type fakeStream[T any] struct {
	ctx  context.Context
	sent []*T
}

func (f *fakeStream[T]) Send(resp *T) error           { f.sent = append(f.sent, resp); return nil }
func (f *fakeStream[T]) Context() context.Context     { return f.ctx }
func (f *fakeStream[T]) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream[T]) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream[T]) SetTrailer(metadata.MD)       {}
func (f *fakeStream[T]) SendMsg(_ any) error          { return nil }
func (f *fakeStream[T]) RecvMsg(_ any) error          { return nil }

func statusEvent(missionID, st string) EventData {
	return EventData{
		EventType: "status",
		Timestamp: time.Now(),
		MissionEvent: &MissionEventData{
			EventType: "status",
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload:   map[string]any{"status": st},
		},
	}
}

func nodeEvent(missionID, nodeID string) EventData {
	return EventData{
		EventType: "node.started",
		Timestamp: time.Now(),
		MissionEvent: &MissionEventData{
			EventType: "node.started",
			Timestamp: time.Now(),
			MissionID: missionID,
			NodeID:    nodeID,
		},
	}
}

// ---- pure helpers ---------------------------------------------------------

func TestMissionEventFromBus(t *testing.T) {
	if got := missionEventFromBus(EventData{EventType: "finding"}, "m-1"); got != nil {
		t.Errorf("non-mission event must map to nil, got %+v", got)
	}
	if got := missionEventFromBus(nodeEvent("other", "n"), "m-1"); got != nil {
		t.Errorf("other mission's event must map to nil, got %+v", got)
	}
	if got := missionEventFromBus(nodeEvent("m-1", "n"), "m-1"); got == nil || got.NodeID != "n" {
		t.Errorf("own mission's event must pass through, got %+v", got)
	}
}

func TestIsTerminalMissionEvent(t *testing.T) {
	if isTerminalMissionEvent(nil) {
		t.Error("nil is not terminal")
	}
	if isTerminalMissionEvent(&MissionEventData{EventType: "node.started"}) {
		t.Error("node events are not terminal")
	}
	if isTerminalMissionEvent(&MissionEventData{EventType: "status", Payload: map[string]any{"status": "running"}}) {
		t.Error("status running is not terminal")
	}
	if !isTerminalMissionEvent(&MissionEventData{EventType: "status", Payload: map[string]any{"status": "completed"}}) {
		t.Error("status completed is terminal")
	}
	if !isTerminalMissionEvent(&MissionEventData{EventType: "status", Payload: map[string]any{"status": "failed"}}) {
		t.Error("status failed is terminal")
	}
}

// ---- RunMission streaming handler ----------------------------------------

func TestRunMission_RequiredFields(t *testing.T) {
	server := NewDaemonServer(&mockDaemon{}, nil, nil)
	stream := &fakeStream[daemonpb.RunMissionResponse]{ctx: context.Background()}

	err := server.RunMission(&daemonpb.RunMissionRequest{TargetId: "t"}, stream)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing definition ID: want InvalidArgument, got %v", err)
	}
	err = server.RunMission(&daemonpb.RunMissionRequest{MissionDefinitionId: "d"}, stream)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing target ID: want InvalidArgument, got %v", err)
	}
}

func TestRunMission_SubscribeError(t *testing.T) {
	daemon := &mockDaemon{
		subscribeFn: func(context.Context, []string, string) (<-chan EventData, error) {
			return nil, errors.New("bus down")
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.RunMissionResponse]{ctx: context.Background()}
	err := server.RunMission(&daemonpb.RunMissionRequest{MissionDefinitionId: "d", TargetId: "t"}, stream)
	if err == nil {
		t.Fatal("subscribe failure must fail the RPC")
	}
}

func TestRunMission_RunError(t *testing.T) {
	events := make(chan EventData)
	daemon := &mockDaemon{
		subscribeFn: func(context.Context, []string, string) (<-chan EventData, error) {
			return events, nil
		},
		runMissionFn: func(context.Context, string, string, map[string]string, string) (string, error) {
			return "", errors.New("definition not found")
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.RunMissionResponse]{ctx: context.Background()}
	err := server.RunMission(&daemonpb.RunMissionRequest{MissionDefinitionId: "d", TargetId: "t"}, stream)
	if err == nil {
		t.Fatal("run failure must fail the RPC")
	}
}

// TestRunMission_StreamsUntilTerminal is the core gibson#1112 PR 3 contract:
// the handler subscribes (unfiltered — the ID is unknown until Run returns),
// filters by the returned mission ID, forwards that mission's events, and
// ends the stream on the projector's terminal status event.
func TestRunMission_StreamsUntilTerminal(t *testing.T) {
	events := make(chan EventData, 4)
	var subscribedMissionID *string
	daemon := &mockDaemon{
		subscribeFn: func(_ context.Context, _ []string, missionID string) (<-chan EventData, error) {
			subscribedMissionID = &missionID
			return events, nil
		},
		runMissionFn: func(context.Context, string, string, map[string]string, string) (string, error) {
			return "m-1", nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.RunMissionResponse]{ctx: context.Background()}

	events <- nodeEvent("other-mission", "x") // filtered out
	events <- nodeEvent("m-1", "recon")       // forwarded
	events <- statusEvent("m-1", "completed") // forwarded, ends stream

	err := server.RunMission(&daemonpb.RunMissionRequest{MissionDefinitionId: "d", TargetId: "t"}, stream)
	if err != nil {
		t.Fatalf("terminal status must end the stream cleanly: %v", err)
	}
	if subscribedMissionID == nil || *subscribedMissionID != "" {
		t.Errorf("Run subscription must be unfiltered (ID unknown), got %v", subscribedMissionID)
	}
	if len(stream.sent) != 2 {
		t.Fatalf("want 2 forwarded events, got %d", len(stream.sent))
	}
	if stream.sent[0].EventType != "node.started" || stream.sent[0].NodeId != "recon" {
		t.Errorf("first event: got %+v", stream.sent[0])
	}
	if stream.sent[1].EventType != "status" || stream.sent[1].MissionId != "m-1" {
		t.Errorf("terminal event: got %+v", stream.sent[1])
	}
}

func TestRunMission_SubscriptionClosedRunContinues(t *testing.T) {
	events := make(chan EventData)
	close(events)
	daemon := &mockDaemon{
		subscribeFn: func(context.Context, []string, string) (<-chan EventData, error) {
			return events, nil
		},
		runMissionFn: func(context.Context, string, string, map[string]string, string) (string, error) {
			return "m-1", nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.RunMissionResponse]{ctx: context.Background()}
	err := server.RunMission(&daemonpb.RunMissionRequest{MissionDefinitionId: "d", TargetId: "t"}, stream)
	if err != nil {
		t.Fatalf("closed subscription is not an RPC failure (run continues detached): %v", err)
	}
}

func TestRunMission_ClientDisconnectRunContinues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events := make(chan EventData)
	daemon := &mockDaemon{
		subscribeFn: func(context.Context, []string, string) (<-chan EventData, error) {
			return events, nil
		},
		runMissionFn: func(context.Context, string, string, map[string]string, string) (string, error) {
			return "m-1", nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.RunMissionResponse]{ctx: ctx}
	err := server.RunMission(&daemonpb.RunMissionRequest{MissionDefinitionId: "d", TargetId: "t"}, stream)
	if err != nil {
		t.Fatalf("client disconnect is a normal end of stream (gibson#1196): %v", err)
	}
}

// ---- ResumeMission streaming handler -------------------------------------

func TestResumeMission_RequiredMissionID(t *testing.T) {
	server := NewDaemonServer(&mockDaemon{}, nil, nil)
	stream := &fakeStream[daemonpb.ResumeMissionResponse]{ctx: context.Background()}
	err := server.ResumeMission(&daemonpb.ResumeMissionRequest{}, stream)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

func TestResumeMission_ErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		errText  string
		wantCode codes.Code
	}{
		{"not found", "mission m-1 not found or not running", codes.NotFound},
		{"not paused", "mission m-1 is not paused", codes.FailedPrecondition},
		{"no checkpoint", "no checkpoint available", codes.FailedPrecondition},
		{"other", "redis on fire", codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan EventData)
			daemon := &mockDaemon{
				subscribeFn: func(context.Context, []string, string) (<-chan EventData, error) {
					return events, nil
				},
				resumeMissionFn: func(context.Context, string) error {
					return errors.New(tc.errText)
				},
			}
			server := NewDaemonServer(daemon, nil, nil)
			stream := &fakeStream[daemonpb.ResumeMissionResponse]{ctx: context.Background()}
			err := server.ResumeMission(&daemonpb.ResumeMissionRequest{MissionId: "m-1"}, stream)
			if status.Code(err) != tc.wantCode {
				t.Errorf("want %v, got %v (%v)", tc.wantCode, status.Code(err), err)
			}
		})
	}
}

// TestResumeMission_StreamsUntilTerminal: the resume subscription is filtered
// server-side (the ID is known up front), events flow until the projector's
// terminal status, and checkpoint metadata rides the first emitted event.
func TestResumeMission_StreamsUntilTerminal(t *testing.T) {
	events := make(chan EventData, 3)
	var subscribedMissionID string
	daemon := &mockDaemon{
		subscribeFn: func(_ context.Context, _ []string, missionID string) (<-chan EventData, error) {
			subscribedMissionID = missionID
			return events, nil
		},
		resumeMissionFn: func(context.Context, string) error { return nil },
		getMissionCheckpointsFn: func(context.Context, string) ([]CheckpointData, error) {
			return []CheckpointData{{CheckpointID: "cp-9"}}, nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.ResumeMissionResponse]{ctx: context.Background()}

	events <- nodeEvent("other", "x")      // filtered out
	events <- nodeEvent("m-1", "recon")    // forwarded
	events <- statusEvent("m-1", "failed") // forwarded, ends stream

	err := server.ResumeMission(&daemonpb.ResumeMissionRequest{MissionId: "m-1"}, stream)
	if err != nil {
		t.Fatalf("terminal status must end the resume stream cleanly: %v", err)
	}
	if subscribedMissionID != "m-1" {
		t.Errorf("resume subscription must be filtered on the mission ID, got %q", subscribedMissionID)
	}
	if len(stream.sent) != 2 {
		t.Fatalf("want 2 forwarded events, got %d", len(stream.sent))
	}
	// Checkpoint metadata rides the first emitted event only.
	if stream.sent[0].CheckpointMetadata == nil {
		t.Error("first resume event must carry checkpoint metadata")
	}
	if stream.sent[1].CheckpointMetadata != nil {
		t.Error("only the first resume event carries checkpoint metadata")
	}
}

func TestResumeMission_ClientDisconnectRunContinues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events := make(chan EventData)
	daemon := &mockDaemon{
		subscribeFn: func(context.Context, []string, string) (<-chan EventData, error) {
			return events, nil
		},
		resumeMissionFn: func(context.Context, string) error { return nil },
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.ResumeMissionResponse]{ctx: ctx}
	err := server.ResumeMission(&daemonpb.ResumeMissionRequest{MissionId: "m-1"}, stream)
	if err != nil {
		t.Fatalf("client disconnect is a normal end of the resume stream: %v", err)
	}
}

func TestResumeMission_SubscribeError(t *testing.T) {
	daemon := &mockDaemon{
		subscribeFn: func(context.Context, []string, string) (<-chan EventData, error) {
			return nil, errors.New("bus down")
		},
	}
	server := NewDaemonServer(daemon, nil, nil)
	stream := &fakeStream[daemonpb.ResumeMissionResponse]{ctx: context.Background()}
	err := server.ResumeMission(&daemonpb.ResumeMissionRequest{MissionId: "m-1"}, stream)
	if status.Code(err) != codes.Internal {
		t.Errorf("subscribe failure must surface as Internal, got %v", err)
	}
}
