package api

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/mission"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockDaemon implements DaemonInterface for testing
type mockDaemon struct {
	statusFn                  func() (DaemonStatus, error)
	listAgentsFn              func(ctx context.Context, kind string) ([]AgentInfoInternal, error)
	getAgentStatusFn          func(ctx context.Context, agentID string) (AgentStatusInternal, error)
	listToolsFn               func(ctx context.Context) ([]ToolInfoInternal, error)
	listPluginsFn             func(ctx context.Context) ([]PluginInfoInternal, error)
	queryPluginFn             func(ctx context.Context, name, method string, params map[string]any) (any, error)
	runMissionFn              func(ctx context.Context, missionDefinitionID string, targetID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error)
	stopMissionFn             func(ctx context.Context, missionID string, force bool) error
	listMissionsFn            func(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]MissionData, int, error)
	subscribeFn               func(ctx context.Context, eventTypes []string, missionID string) (<-chan EventData, error)
	startComponentFn          func(ctx context.Context, kind string, name string) (StartComponentResult, error)
	stopComponentFn           func(ctx context.Context, kind string, name string, force bool) (StopComponentResult, error)
	pauseMissionFn            func(ctx context.Context, missionID string, force bool) error
	resumeMissionFn           func(ctx context.Context, missionID string) (<-chan MissionEventData, error)
	getMissionHistoryFn       func(ctx context.Context, name string, limit int, offset int) ([]MissionRunData, int, error)
	getMissionCheckpointsFn   func(ctx context.Context, missionID string) ([]CheckpointData, error)
	getCheckpointPayloadFn    func(ctx context.Context, missionID, checkpointID string) (*CheckpointData, error)
	rewindMissionFn           func(ctx context.Context, missionID, targetCheckpointID string) (string, error)
	buildComponentFn          func(ctx context.Context, kind string, name string) (BuildComponentResult, error)
	showComponentFn           func(ctx context.Context, kind string, name string) (ComponentInfoInternal, error)
	getComponentLogsFn        func(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan LogEntryData, error)
	listMissionDefinitionsFn  func(ctx context.Context, limit int, offset int) ([]MissionDefinitionData, int, error)
	getMissionDefinitionFn    func(ctx context.Context, name string) (*missionpb.MissionDefinition, error)
	createMissionFn           func(ctx context.Context, req CreateMissionData) (CreateMissionResultData, error)
	createMissionDefinitionFn func(ctx context.Context, req CreateMissionDefinitionData) (CreateMissionDefinitionResultData, error)
	updateMissionDefinitionFn func(ctx context.Context, req UpdateMissionDefinitionData) (UpdateMissionDefinitionResultData, error)
}

func (m *mockDaemon) Status() (DaemonStatus, error) {
	if m.statusFn != nil {
		return m.statusFn()
	}
	return DaemonStatus{}, nil
}

func (m *mockDaemon) ListAgents(ctx context.Context, kind string) ([]AgentInfoInternal, error) {
	if m.listAgentsFn != nil {
		return m.listAgentsFn(ctx, kind)
	}
	return nil, nil
}

func (m *mockDaemon) GetAgentStatus(ctx context.Context, agentID string) (AgentStatusInternal, error) {
	if m.getAgentStatusFn != nil {
		return m.getAgentStatusFn(ctx, agentID)
	}
	return AgentStatusInternal{}, nil
}

func (m *mockDaemon) ListTools(ctx context.Context) ([]ToolInfoInternal, error) {
	if m.listToolsFn != nil {
		return m.listToolsFn(ctx)
	}
	return nil, nil
}

func (m *mockDaemon) ListPlugins(ctx context.Context) ([]PluginInfoInternal, error) {
	if m.listPluginsFn != nil {
		return m.listPluginsFn(ctx)
	}
	return nil, nil
}

func (m *mockDaemon) QueryPlugin(ctx context.Context, name, method string, params map[string]any) (any, error) {
	if m.queryPluginFn != nil {
		return m.queryPluginFn(ctx, name, method, params)
	}
	return nil, nil
}

func (m *mockDaemon) RunMission(ctx context.Context, missionDefinitionID string, targetID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
	if m.runMissionFn != nil {
		return m.runMissionFn(ctx, missionDefinitionID, targetID, variables, memoryContinuity)
	}
	return nil, nil
}

func (m *mockDaemon) StopMission(ctx context.Context, missionID string, force bool) error {
	if m.stopMissionFn != nil {
		return m.stopMissionFn(ctx, missionID, force)
	}
	return nil
}

func (m *mockDaemon) ListMissions(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]MissionData, int, error) {
	if m.listMissionsFn != nil {
		return m.listMissionsFn(ctx, activeOnly, statusFilter, namePattern, limit, offset)
	}
	return nil, 0, nil
}

func (m *mockDaemon) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan EventData, error) {
	if m.subscribeFn != nil {
		return m.subscribeFn(ctx, eventTypes, missionID)
	}
	return nil, nil
}

func (m *mockDaemon) StartComponent(ctx context.Context, kind string, name string) (StartComponentResult, error) {
	if m.startComponentFn != nil {
		return m.startComponentFn(ctx, kind, name)
	}
	return StartComponentResult{}, nil
}

func (m *mockDaemon) StopComponent(ctx context.Context, kind string, name string, force bool) (StopComponentResult, error) {
	if m.stopComponentFn != nil {
		return m.stopComponentFn(ctx, kind, name, force)
	}
	return StopComponentResult{}, nil
}

func (m *mockDaemon) PauseMission(ctx context.Context, missionID string, force bool) error {
	if m.pauseMissionFn != nil {
		return m.pauseMissionFn(ctx, missionID, force)
	}
	return nil
}

func (m *mockDaemon) ResumeMission(ctx context.Context, missionID string) (<-chan MissionEventData, error) {
	if m.resumeMissionFn != nil {
		return m.resumeMissionFn(ctx, missionID)
	}
	return nil, nil
}

func (m *mockDaemon) GetMissionHistory(ctx context.Context, name string, limit int, offset int) ([]MissionRunData, int, error) {
	if m.getMissionHistoryFn != nil {
		return m.getMissionHistoryFn(ctx, name, limit, offset)
	}
	return nil, 0, nil
}

func (m *mockDaemon) GetMissionCheckpoints(ctx context.Context, missionID string) ([]CheckpointData, error) {
	if m.getMissionCheckpointsFn != nil {
		return m.getMissionCheckpointsFn(ctx, missionID)
	}
	return nil, nil
}

func (m *mockDaemon) GetMissionCheckpointPayload(ctx context.Context, missionID, checkpointID string) (*CheckpointData, error) {
	if m.getCheckpointPayloadFn != nil {
		return m.getCheckpointPayloadFn(ctx, missionID, checkpointID)
	}
	return nil, nil
}

func (m *mockDaemon) RewindMission(ctx context.Context, missionID, targetCheckpointID string) (string, error) {
	if m.rewindMissionFn != nil {
		return m.rewindMissionFn(ctx, missionID, targetCheckpointID)
	}
	return "", nil
}

func (m *mockDaemon) BuildComponent(ctx context.Context, kind string, name string) (BuildComponentResult, error) {
	if m.buildComponentFn != nil {
		return m.buildComponentFn(ctx, kind, name)
	}
	return BuildComponentResult{}, nil
}

func (m *mockDaemon) ShowComponent(ctx context.Context, kind string, name string) (ComponentInfoInternal, error) {
	if m.showComponentFn != nil {
		return m.showComponentFn(ctx, kind, name)
	}
	return ComponentInfoInternal{}, nil
}

func (m *mockDaemon) GetComponentLogs(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan LogEntryData, error) {
	if m.getComponentLogsFn != nil {
		return m.getComponentLogsFn(ctx, kind, name, follow, lines)
	}
	return nil, nil
}

func (m *mockDaemon) ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]MissionDefinitionData, int, error) {
	if m.listMissionDefinitionsFn != nil {
		return m.listMissionDefinitionsFn(ctx, limit, offset)
	}
	return nil, 0, nil
}

func (m *mockDaemon) GetMissionDefinition(ctx context.Context, name string) (*missionpb.MissionDefinition, error) {
	if m.getMissionDefinitionFn != nil {
		return m.getMissionDefinitionFn(ctx, name)
	}
	return nil, nil
}

func (m *mockDaemon) CreateMission(ctx context.Context, req CreateMissionData) (CreateMissionResultData, error) {
	if m.createMissionFn != nil {
		return m.createMissionFn(ctx, req)
	}
	return CreateMissionResultData{}, nil
}

func (m *mockDaemon) CreateMissionDefinition(ctx context.Context, req CreateMissionDefinitionData) (CreateMissionDefinitionResultData, error) {
	if m.createMissionDefinitionFn != nil {
		return m.createMissionDefinitionFn(ctx, req)
	}
	return CreateMissionDefinitionResultData{}, nil
}

func (m *mockDaemon) UpdateMissionDefinition(ctx context.Context, req UpdateMissionDefinitionData) (UpdateMissionDefinitionResultData, error) {
	if m.updateMissionDefinitionFn != nil {
		return m.updateMissionDefinitionFn(ctx, req)
	}
	return UpdateMissionDefinitionResultData{}, nil
}

func (m *mockDaemon) RequestShutdown(ctx context.Context, force bool, timeoutSeconds int32) error {
	return nil
}

func (m *mockDaemon) RefreshToolCatalog(ctx context.Context) (bool, string, error) {
	return false, "mock daemon does not run a catalog refresher", nil
}

// mockServerStream implements grpc.ServerStreamingServer[MissionEvent] for testing
type mockServerStream struct {
	ctx       context.Context
	sentCount int
	events    []*daemonpb.RunMissionResponse
}

func (m *mockServerStream) Send(event *daemonpb.RunMissionResponse) error {
	m.sentCount++
	m.events = append(m.events, event)
	return nil
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockServerStream) SetTrailer(md metadata.MD) {
}

func (m *mockServerStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(msg interface{}) error {
	return nil
}

// TestRunMission_RejectsMissingIDs verifies the reference-only RunMission
// handler rejects requests that omit mission_definition_id or target_id.
// The legacy MissionYaml / MissionDefinitionID branches were removed under spec
// mission-api-only-cleanup.
func TestRunMission_RejectsMissingIDs(t *testing.T) {
	tests := []struct {
		name     string
		req      *daemonpb.RunMissionRequest
		wantCode codes.Code
	}{
		{
			name:     "missing mission_definition_id",
			req:      &daemonpb.RunMissionRequest{TargetId: "target-1"},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "missing target_id",
			req:      &daemonpb.RunMissionRequest{MissionDefinitionId: "def-1"},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &mockDaemon{}
			server := NewDaemonServer(daemon, nil, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream := &mockServerStream{ctx: ctx}

			err := server.RunMission(tt.req, stream)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			st, _ := status.FromError(err)
			if st.Code() != tt.wantCode {
				t.Fatalf("expected %v, got %v (err=%v)", tt.wantCode, st.Code(), err)
			}
		})
	}
}

// TestCreateMissionDefinition verifies that a valid MissionDefinition is
// forwarded to the daemon and the response is returned to the caller.
func TestCreateMissionDefinition_HappyPath(t *testing.T) {
	daemon := &mockDaemon{
		createMissionDefinitionFn: func(ctx context.Context, req CreateMissionDefinitionData) (CreateMissionDefinitionResultData, error) {
			if req.Definition == nil {
				t.Fatalf("expected definition, got nil")
			}
			if req.Definition.Name != "my-def" {
				t.Fatalf("expected name my-def, got %q", req.Definition.Name)
			}
			return CreateMissionDefinitionResultData{
				MissionDefinitionID: "01GY-DEF",
				Info: MissionDefinitionData{
					Name:        req.Definition.Name,
					Version:     req.Definition.Version,
					Description: req.Definition.Description,
					NodeCount:   0,
				},
			}, nil
		},
	}
	server := NewDaemonServer(daemon, nil, nil)

	resp, err := server.CreateMissionDefinition(context.Background(), &daemonpb.CreateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{
			Name:        "my-def",
			Version:     "1.0.0",
			Description: "test",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.MissionDefinitionId != "01GY-DEF" {
		t.Fatalf("expected mission_definition_id 01GY-DEF, got %q", resp.MissionDefinitionId)
	}
	if resp.Info == nil || resp.Info.Name != "my-def" {
		t.Fatalf("expected info.name = my-def, got %+v", resp.Info)
	}
}

// TestCreateMissionDefinition_RejectsMissingName verifies the validator rejects
// a definition without a name field.
func TestCreateMissionDefinition_RejectsMissingName(t *testing.T) {
	daemon := &mockDaemon{}
	server := NewDaemonServer(daemon, nil, nil)

	_, err := server.CreateMissionDefinition(context.Background(), &daemonpb.CreateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{},
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", st.Code())
	}
}

// Keep a compile-time reference so stray unused imports don't break the test.
var _ = mission.MissionStatusPending
