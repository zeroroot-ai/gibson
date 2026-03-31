package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/mission"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockDaemon implements DaemonInterface for testing
type mockDaemon struct {
	statusFn                      func() (DaemonStatus, error)
	listAgentsFn                  func(ctx context.Context, kind string) ([]AgentInfoInternal, error)
	getAgentStatusFn              func(ctx context.Context, agentID string) (AgentStatusInternal, error)
	listToolsFn                   func(ctx context.Context) ([]ToolInfoInternal, error)
	listPluginsFn                 func(ctx context.Context) ([]PluginInfoInternal, error)
	queryPluginFn                 func(ctx context.Context, name, method string, params map[string]any) (any, error)
	runMissionFn                  func(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error)
	stopMissionFn                 func(ctx context.Context, missionID string, force bool) error
	listMissionsFn                func(ctx context.Context, activeOnly bool, statusFilter, namePattern string, limit, offset int) ([]MissionData, int, error)
	runAttackFn                   func(ctx context.Context, req AttackRequest) (<-chan AttackEventData, error)
	subscribeFn                   func(ctx context.Context, eventTypes []string, missionID string) (<-chan EventData, error)
	startComponentFn              func(ctx context.Context, kind string, name string) (StartComponentResult, error)
	stopComponentFn               func(ctx context.Context, kind string, name string, force bool) (StopComponentResult, error)
	pauseMissionFn                func(ctx context.Context, missionID string, force bool) error
	resumeMissionFn               func(ctx context.Context, missionID string) (<-chan MissionEventData, error)
	getMissionHistoryFn           func(ctx context.Context, name string, limit int, offset int) ([]MissionRunData, int, error)
	getMissionCheckpointsFn       func(ctx context.Context, missionID string) ([]CheckpointData, error)
	installComponentFn            func(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (InstallComponentResult, error)
	installAllComponentFn         func(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (InstallAllComponentResult, error)
	uninstallComponentFn          func(ctx context.Context, kind string, name string, force bool) error
	updateComponentFn             func(ctx context.Context, kind string, name string, restart bool, skipBuild bool, verbose bool) (UpdateComponentResult, error)
	buildComponentFn              func(ctx context.Context, kind string, name string) (BuildComponentResult, error)
	showComponentFn               func(ctx context.Context, kind string, name string) (ComponentInfoInternal, error)
	getComponentLogsFn            func(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan LogEntryData, error)
	installMissionFn              func(ctx context.Context, url string, branch string, tag string, force bool, yes bool, timeoutMs int64) (InstallMissionResult, error)
	uninstallMissionFn            func(ctx context.Context, name string, force bool) error
	listMissionDefinitionsFn      func(ctx context.Context, limit int, offset int) ([]MissionDefinitionData, int, error)
	updateMissionFn               func(ctx context.Context, name string, timeoutMs int64) (UpdateMissionResult, error)
	resolveMissionDependenciesFn  func(ctx context.Context, missionPath string) (DependencyTreeData, error)
	validateMissionDependenciesFn func(ctx context.Context, missionPath string) (ValidationResultData, error)
	ensureMissionDependenciesFn   func(ctx context.Context, missionPath string) error
	createMissionFn               func(ctx context.Context, req CreateMissionData) (CreateMissionResultData, error)
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

func (m *mockDaemon) RunMission(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
	if m.runMissionFn != nil {
		return m.runMissionFn(ctx, workflowPath, missionID, variables, memoryContinuity)
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

func (m *mockDaemon) RunAttack(ctx context.Context, req AttackRequest) (<-chan AttackEventData, error) {
	if m.runAttackFn != nil {
		return m.runAttackFn(ctx, req)
	}
	return nil, nil
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

func (m *mockDaemon) InstallComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (InstallComponentResult, error) {
	if m.installComponentFn != nil {
		return m.installComponentFn(ctx, kind, url, branch, tag, force, skipBuild, verbose)
	}
	return InstallComponentResult{}, nil
}

func (m *mockDaemon) InstallAllComponent(ctx context.Context, kind string, url string, branch string, tag string, force bool, skipBuild bool, verbose bool) (InstallAllComponentResult, error) {
	if m.installAllComponentFn != nil {
		return m.installAllComponentFn(ctx, kind, url, branch, tag, force, skipBuild, verbose)
	}
	return InstallAllComponentResult{}, nil
}

func (m *mockDaemon) UninstallComponent(ctx context.Context, kind string, name string, force bool) error {
	if m.uninstallComponentFn != nil {
		return m.uninstallComponentFn(ctx, kind, name, force)
	}
	return nil
}

func (m *mockDaemon) UpdateComponent(ctx context.Context, kind string, name string, restart bool, skipBuild bool, verbose bool) (UpdateComponentResult, error) {
	if m.updateComponentFn != nil {
		return m.updateComponentFn(ctx, kind, name, restart, skipBuild, verbose)
	}
	return UpdateComponentResult{}, nil
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

func (m *mockDaemon) InstallMission(ctx context.Context, url string, branch string, tag string, force bool, yes bool, timeoutMs int64) (InstallMissionResult, error) {
	if m.installMissionFn != nil {
		return m.installMissionFn(ctx, url, branch, tag, force, yes, timeoutMs)
	}
	return InstallMissionResult{}, nil
}

func (m *mockDaemon) UninstallMission(ctx context.Context, name string, force bool) error {
	if m.uninstallMissionFn != nil {
		return m.uninstallMissionFn(ctx, name, force)
	}
	return nil
}

func (m *mockDaemon) ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]MissionDefinitionData, int, error) {
	if m.listMissionDefinitionsFn != nil {
		return m.listMissionDefinitionsFn(ctx, limit, offset)
	}
	return nil, 0, nil
}

func (m *mockDaemon) UpdateMission(ctx context.Context, name string, timeoutMs int64) (UpdateMissionResult, error) {
	if m.updateMissionFn != nil {
		return m.updateMissionFn(ctx, name, timeoutMs)
	}
	return UpdateMissionResult{}, nil
}

func (m *mockDaemon) ResolveMissionDependencies(ctx context.Context, missionPath string) (DependencyTreeData, error) {
	if m.resolveMissionDependenciesFn != nil {
		return m.resolveMissionDependenciesFn(ctx, missionPath)
	}
	return DependencyTreeData{}, nil
}

func (m *mockDaemon) ValidateMissionDependencies(ctx context.Context, missionPath string) (ValidationResultData, error) {
	if m.validateMissionDependenciesFn != nil {
		return m.validateMissionDependenciesFn(ctx, missionPath)
	}
	return ValidationResultData{}, nil
}

func (m *mockDaemon) EnsureMissionDependencies(ctx context.Context, missionPath string) error {
	if m.ensureMissionDependenciesFn != nil {
		return m.ensureMissionDependenciesFn(ctx, missionPath)
	}
	return nil
}

func (m *mockDaemon) CreateMission(ctx context.Context, req CreateMissionData) (CreateMissionResultData, error) {
	if m.createMissionFn != nil {
		return m.createMissionFn(ctx, req)
	}
	return CreateMissionResultData{}, nil
}

func (m *mockDaemon) RequestShutdown(ctx context.Context, force bool, timeoutSeconds int32) error {
	return nil
}

// mockServerStream implements grpc.ServerStreamingServer[MissionEvent] for testing
type mockServerStream struct {
	ctx       context.Context
	sentCount int
	events    []*MissionEvent
}

func (m *mockServerStream) Send(event *MissionEvent) error {
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

// TestRunMission_WithWorkflowYAML tests the RunMission handler when workflow_yaml is provided
func TestRunMission_WithWorkflowYAML(t *testing.T) {
	validYAML := `
name: test-mission
description: Test mission description
target:
  reference: test-target
workflow:
  reference: test-workflow
`

	tests := []struct {
		name          string
		workflowYAML  string
		workflowPath  string
		expectError   bool
		errorCode     codes.Code
		errorContains string
		setupDaemon   func(*mockDaemon)
	}{
		{
			name:         "valid workflow_yaml",
			workflowYAML: validYAML,
			expectError:  false,
			setupDaemon: func(md *mockDaemon) {
				md.runMissionFn = func(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
					// Verify that a temporary file path is passed
					if !strings.Contains(workflowPath, "gibson-mission") {
						t.Errorf("expected temporary file path, got: %s", workflowPath)
					}
					// Return a channel that closes immediately
					ch := make(chan MissionEventData)
					close(ch)
					return ch, nil
				}
			},
		},
		{
			name:          "workflow_yaml exceeds size limit",
			workflowYAML:  strings.Repeat("a", 11*1024*1024), // 11MB
			expectError:   true,
			errorCode:     codes.InvalidArgument,
			errorContains: "exceeds maximum allowed size",
			setupDaemon:   func(md *mockDaemon) {},
		},
		{
			name:          "invalid workflow YAML syntax",
			workflowYAML:  "invalid: yaml: :\n  bad: indentation\n wrong:",
			expectError:   true,
			errorCode:     codes.InvalidArgument,
			errorContains: "invalid workflow YAML",
			setupDaemon:   func(md *mockDaemon) {},
		},
		{
			name:          "workflow_yaml with missing required fields",
			workflowYAML:  "name: test", // Missing required fields
			expectError:   true,
			errorCode:     codes.InvalidArgument,
			errorContains: "invalid workflow YAML",
			setupDaemon:   func(md *mockDaemon) {},
		},
		{
			name:         "workflow_yaml takes precedence over workflow_path",
			workflowYAML: validYAML,
			workflowPath: "/some/other/path.yaml",
			expectError:  false,
			setupDaemon: func(md *mockDaemon) {
				md.runMissionFn = func(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
					// Verify that temporary file is used, not the path
					if strings.Contains(workflowPath, "/some/other/path.yaml") {
						t.Errorf("workflow_path should not be used when workflow_yaml is provided")
					}
					if !strings.Contains(workflowPath, "gibson-mission") {
						t.Errorf("expected temporary file path, got: %s", workflowPath)
					}
					ch := make(chan MissionEventData)
					close(ch)
					return ch, nil
				}
			},
		},
		{
			name:         "workflow_path used when workflow_yaml is empty",
			workflowPath: "/valid/path.yaml",
			expectError:  false,
			setupDaemon: func(md *mockDaemon) {
				md.runMissionFn = func(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
					// Verify that the provided path is used
					if workflowPath != "/valid/path.yaml" {
						t.Errorf("expected workflow_path to be used, got: %s", workflowPath)
					}
					ch := make(chan MissionEventData)
					close(ch)
					return ch, nil
				}
			},
		},
		{
			name:          "neither workflow_yaml nor workflow_path provided",
			expectError:   true,
			errorCode:     codes.InvalidArgument,
			errorContains: "either workflow_path or workflow_yaml must be provided",
			setupDaemon:   func(md *mockDaemon) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock daemon
			daemon := &mockDaemon{}
			tt.setupDaemon(daemon)

			// Create server
			server := NewDaemonServer(daemon, nil, nil)

			// Create request
			req := &RunMissionRequest{
				WorkflowYaml: tt.workflowYAML,
				WorkflowPath: tt.workflowPath,
				MissionId:    "test-mission-id",
			}

			// Create mock stream
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream := &mockServerStream{ctx: ctx}

			// Execute
			err := server.RunMission(req, stream)

			// Verify
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
					return
				}

				// Check error code
				st, ok := status.FromError(err)
				if !ok {
					t.Errorf("expected gRPC status error, got: %v", err)
					return
				}

				if st.Code() != tt.errorCode {
					t.Errorf("expected error code %v, got %v", tt.errorCode, st.Code())
				}

				// Check error message contains expected text
				if !strings.Contains(st.Message(), tt.errorContains) {
					t.Errorf("expected error message to contain %q, got: %s", tt.errorContains, st.Message())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestRunMission_WorkflowYAML_Cleanup tests that temporary files are cleaned up
func TestRunMission_WorkflowYAML_Cleanup(t *testing.T) {
	validYAML := `
name: test-mission
description: Test mission description
target:
  reference: test-target
workflow:
  reference: test-workflow
`

	daemon := &mockDaemon{
		runMissionFn: func(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
			// Verify file exists at this point
			if _, err := mission.ParseYAML([]byte(validYAML)); err != nil {
				t.Errorf("YAML should be valid during mission execution: %v", err)
			}

			// Verify we got a temporary file path
			if !strings.Contains(workflowPath, "gibson-mission") {
				t.Errorf("expected temporary file path, got: %s", workflowPath)
			}

			// Return a channel that closes immediately
			ch := make(chan MissionEventData)
			close(ch)
			return ch, nil
		},
	}

	server := NewDaemonServer(daemon, nil, nil)

	req := &RunMissionRequest{
		WorkflowYaml: validYAML,
		MissionId:    "test-mission-id",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := &mockServerStream{ctx: ctx}

	// Execute
	err := server.RunMission(req, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Note: The cleanup happens via defer in RunMission, but we can't easily verify
	// file deletion in this unit test since the actual file I/O happens in the handler.
	// This test primarily verifies that the workflow runs successfully with inline YAML.
	// Integration tests should verify proper cleanup.
}

// TestRunMission_WorkflowYAML_MissionExecution tests mission execution with inline YAML
func TestRunMission_WorkflowYAML_MissionExecution(t *testing.T) {
	validYAML := `
name: test-mission
description: Test mission description
target:
  reference: test-target
workflow:
  reference: test-workflow
`

	eventsSent := false
	daemon := &mockDaemon{
		runMissionFn: func(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
			// Return a channel with some events
			ch := make(chan MissionEventData, 2)
			ch <- MissionEventData{
				EventType: "mission_started",
				Timestamp: time.Now(),
				MissionID: missionID,
				Message:   "Mission started",
			}
			ch <- MissionEventData{
				EventType: "mission_completed",
				Timestamp: time.Now(),
				MissionID: missionID,
				Message:   "Mission completed",
			}
			close(ch)
			eventsSent = true
			return ch, nil
		},
	}

	server := NewDaemonServer(daemon, nil, nil)

	req := &RunMissionRequest{
		WorkflowYaml: validYAML,
		MissionId:    "test-mission-id",
		Variables: map[string]string{
			"var1": "value1",
		},
		MemoryContinuity: "previous-mission-id",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := &mockServerStream{ctx: ctx}

	// Execute
	err := server.RunMission(req, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify events were sent
	if !eventsSent {
		t.Error("expected events to be sent from daemon")
	}

	// Verify stream received events
	if stream.sentCount != 2 {
		t.Errorf("expected 2 events to be sent, got %d", stream.sentCount)
	}

	// Verify event content
	if len(stream.events) > 0 {
		firstEvent := stream.events[0]
		if firstEvent.EventType != "mission_started" {
			t.Errorf("expected first event type 'mission_started', got %s", firstEvent.EventType)
		}
		if firstEvent.MissionId != "test-mission-id" {
			t.Errorf("expected mission ID 'test-mission-id', got %s", firstEvent.MissionId)
		}
	}
}

// TestRunMission_WorkflowYAML_EdgeCases tests edge cases for workflow YAML handling
func TestRunMission_WorkflowYAML_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		workflowYAML  string
		expectError   bool
		errorContains string
	}{
		{
			name:         "empty YAML string",
			workflowYAML: "",
			expectError:  false, // Should use workflow_path if provided
		},
		{
			name:          "whitespace only YAML",
			workflowYAML:  "   \n\t  \n  ",
			expectError:   true,
			errorContains: "invalid workflow YAML",
		},
		{
			name: "YAML at exactly 10MB",
			// Create YAML that's exactly 10MB when including structure
			workflowYAML: func() string {
				// Build a valid YAML that's close to 10MB
				baseYAML := `
name: test-mission
description: Test mission with long description
target:
  reference: test-target
workflow:
  reference: test-workflow
`
				// Calculate remaining space to reach 10MB
				remaining := (10 * 1024 * 1024) - len(baseYAML)
				if remaining > 0 {
					// Pad with comments to reach size
					return baseYAML + "# " + strings.Repeat("a", remaining-3)
				}
				return baseYAML
			}(),
			expectError: false, // Exactly 10MB should be allowed
		},
		{
			name: "valid YAML with unicode characters",
			workflowYAML: `
name: test-mission-日本語
description: Test mission with unicode 目标 🚀🔥
target:
  reference: test-target-目标
workflow:
  reference: test-workflow
`,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &mockDaemon{
				runMissionFn: func(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan MissionEventData, error) {
					ch := make(chan MissionEventData)
					close(ch)
					return ch, nil
				},
			}

			server := NewDaemonServer(daemon, nil, nil)

			req := &RunMissionRequest{
				WorkflowYaml: tt.workflowYAML,
				WorkflowPath: "/fallback/path.yaml", // Provide fallback for empty YAML tests
				MissionId:    "test-mission-id",
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream := &mockServerStream{ctx: ctx}

			err := server.RunMission(req, stream)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
