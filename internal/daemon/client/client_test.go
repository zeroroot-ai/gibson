package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/daemon"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
)

// TestConvertProtoStatus tests the convertProtoStatus function.
func TestConvertProtoStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    *api.StatusResponse
		expected *daemon.DaemonStatus
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name: "complete status",
			input: &api.StatusResponse{
				Running:            true,
				Pid:                12345,
				StartTime:          1640000000,
				Uptime:             "2h30m15s",
				GrpcAddress:        "localhost:50002",
				RegistryType:       "embedded",
				RegistryAddr:       "embedded://localhost:2379",
				CallbackAddr:       "localhost:50001",
				AgentCount:         5,
				MissionCount:       10,
				ActiveMissionCount: 2,
			},
			expected: &daemon.DaemonStatus{
				Running:      true,
				PID:          12345,
				StartTime:    time.Unix(1640000000, 0),
				Uptime:       "2h30m15s",
				GRPCAddress:  "localhost:50002",
				RegistryType: "embedded",
				RegistryAddr: "embedded://localhost:2379",
				CallbackAddr: "localhost:50001",
				AgentCount:   5,
			},
		},
		{
			name: "zero values",
			input: &api.StatusResponse{
				Running:      false,
				Pid:          0,
				StartTime:    0,
				Uptime:       "",
				GrpcAddress:  "",
				RegistryType: "",
				RegistryAddr: "",
				CallbackAddr: "",
				AgentCount:   0,
			},
			expected: &daemon.DaemonStatus{
				Running:      false,
				PID:          0,
				StartTime:    time.Unix(0, 0),
				Uptime:       "",
				GRPCAddress:  "",
				RegistryType: "",
				RegistryAddr: "",
				CallbackAddr: "",
				AgentCount:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProtoStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertProtoAgents tests the convertProtoAgents function.
func TestConvertProtoAgents(t *testing.T) {
	tests := []struct {
		name     string
		input    []*api.AgentInfo
		expected []AgentInfo
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: []AgentInfo{},
		},
		{
			name:     "empty slice",
			input:    []*api.AgentInfo{},
			expected: []AgentInfo{},
		},
		{
			name: "single agent",
			input: []*api.AgentInfo{
				{
					Id:           "agent-1",
					Name:         "prompt-injection",
					Kind:         "agent",
					Version:      "1.0.0",
					Endpoint:     "localhost:50100",
					Capabilities: []string{"llm", "web"},
					Health:       "healthy",
					LastSeen:     1640000000,
				},
			},
			expected: []AgentInfo{
				{
					Name:        "prompt-injection",
					Version:     "1.0.0",
					Description: "",
					Address:     "localhost:50100",
					Status:      "healthy",
				},
			},
		},
		{
			name: "multiple agents",
			input: []*api.AgentInfo{
				{
					Name:     "agent-1",
					Version:  "1.0.0",
					Endpoint: "localhost:50100",
					Health:   "healthy",
				},
				{
					Name:     "agent-2",
					Version:  "2.0.0",
					Endpoint: "localhost:50101",
					Health:   "degraded",
				},
			},
			expected: []AgentInfo{
				{
					Name:        "agent-1",
					Version:     "1.0.0",
					Description: "",
					Address:     "localhost:50100",
					Status:      "healthy",
				},
				{
					Name:        "agent-2",
					Version:     "2.0.0",
					Description: "",
					Address:     "localhost:50101",
					Status:      "degraded",
				},
			},
		},
		{
			name: "nil elements are skipped",
			input: []*api.AgentInfo{
				{
					Name:     "agent-1",
					Version:  "1.0.0",
					Endpoint: "localhost:50100",
					Health:   "healthy",
				},
				nil,
				{
					Name:     "agent-2",
					Version:  "2.0.0",
					Endpoint: "localhost:50101",
					Health:   "healthy",
				},
			},
			expected: []AgentInfo{
				{
					Name:        "agent-1",
					Version:     "1.0.0",
					Description: "",
					Address:     "localhost:50100",
					Status:      "healthy",
				},
				{
					Name:        "agent-2",
					Version:     "2.0.0",
					Description: "",
					Address:     "localhost:50101",
					Status:      "healthy",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProtoAgents(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertProtoTools tests the convertProtoTools function.
func TestConvertProtoTools(t *testing.T) {
	tests := []struct {
		name     string
		input    []*api.ToolInfo
		expected []ToolInfo
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: []ToolInfo{},
		},
		{
			name:     "empty slice",
			input:    []*api.ToolInfo{},
			expected: []ToolInfo{},
		},
		{
			name: "single tool",
			input: []*api.ToolInfo{
				{
					Id:          "tool-1",
					Name:        "nmap",
					Version:     "7.92",
					Endpoint:    "localhost:50200",
					Description: "Network scanner",
					Health:      "healthy",
					LastSeen:    1640000000,
				},
			},
			expected: []ToolInfo{
				{
					Name:        "nmap",
					Version:     "7.92",
					Description: "Network scanner",
					Address:     "localhost:50200",
					Status:      "healthy",
				},
			},
		},
		{
			name: "multiple tools with nil element",
			input: []*api.ToolInfo{
				{
					Name:        "nmap",
					Version:     "7.92",
					Description: "Network scanner",
					Endpoint:    "localhost:50200",
					Health:      "healthy",
				},
				nil,
				{
					Name:        "sqlmap",
					Version:     "1.5",
					Description: "SQL injection tool",
					Endpoint:    "localhost:50201",
					Health:      "healthy",
				},
			},
			expected: []ToolInfo{
				{
					Name:        "nmap",
					Version:     "7.92",
					Description: "Network scanner",
					Address:     "localhost:50200",
					Status:      "healthy",
				},
				{
					Name:        "sqlmap",
					Version:     "1.5",
					Description: "SQL injection tool",
					Address:     "localhost:50201",
					Status:      "healthy",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProtoTools(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertProtoPlugins tests the convertProtoPlugins function.
func TestConvertProtoPlugins(t *testing.T) {
	tests := []struct {
		name     string
		input    []*api.PluginInfo
		expected []PluginInfo
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: []PluginInfo{},
		},
		{
			name:     "empty slice",
			input:    []*api.PluginInfo{},
			expected: []PluginInfo{},
		},
		{
			name: "single plugin",
			input: []*api.PluginInfo{
				{
					Id:          "plugin-1",
					Name:        "mitre-lookup",
					Version:     "1.0.0",
					Endpoint:    "localhost:50300",
					Description: "MITRE ATT&CK lookup plugin",
					Health:      "healthy",
					LastSeen:    1640000000,
				},
			},
			expected: []PluginInfo{
				{
					Name:        "mitre-lookup",
					Version:     "1.0.0",
					Description: "MITRE ATT&CK lookup plugin",
					Address:     "localhost:50300",
					Status:      "healthy",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProtoPlugins(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertProtoMissionEvent tests the convertProtoMissionEvent function.
func TestConvertProtoMissionEvent(t *testing.T) {
	tests := []struct {
		name     string
		input    *api.RunMissionResponse
		expected MissionEvent
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: MissionEvent{},
		},
		{
			name: "complete mission event",
			input: &api.RunMissionResponse{
				EventType: "mission_started",
				Timestamp: 1640000000,
				MissionId: "mission-1",
				NodeId:    "node-1",
				Message:   "Mission started successfully",
				Data: api.MapToTypedMap(map[string]any{
					"workflow": "attack.yaml",
				}),
				Error: "",
			},
			expected: MissionEvent{
				Type:      "mission_started",
				Timestamp: time.Unix(1640000000, 0),
				Message:   "Mission started successfully",
				Data: map[string]interface{}{
					"workflow": "attack.yaml",
				},
			},
		},
		{
			name: "mission event with no data",
			input: &api.RunMissionResponse{
				EventType: "mission_completed",
				Timestamp: 1640000100,
				Message:   "Mission completed",
				Data:      nil,
			},
			expected: MissionEvent{
				Type:      "mission_completed",
				Timestamp: time.Unix(1640000100, 0),
				Message:   "Mission completed",
				Data:      nil,
			},
		},
		{
			name: "mission event with empty data",
			input: &api.RunMissionResponse{
				EventType: "mission.finding",
				Timestamp: 1640000200,
				Message:   "Found vulnerability",
				Data:      api.MapToTypedMap(map[string]any{}),
			},
			expected: MissionEvent{
				Type:      "mission.finding",
				Timestamp: time.Unix(1640000200, 0),
				Message:   "Found vulnerability",
				Data:      map[string]interface{}{}, // Empty map
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProtoMissionEvent(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertProtoAttackEvent tests the convertProtoAttackEvent function.
func TestConvertProtoAttackEvent(t *testing.T) {
	tests := []struct {
		name     string
		input    *api.RunAttackResponse
		expected AttackEvent
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: AttackEvent{},
		},
		{
			name: "complete attack event",
			input: &api.RunAttackResponse{
				EventType: "attack.started",
				Timestamp: 1640000000,
				AttackId:  "attack-1",
				Message:   "Attack started",
				Data: api.MapToTypedMap(map[string]any{
					"target": "http://example.com",
				}),
				Error: "",
			},
			expected: AttackEvent{
				Type:      "attack.started",
				Timestamp: time.Unix(1640000000, 0),
				Message:   "Attack started",
				Severity:  "", // Not in proto
				Data: map[string]interface{}{
					"target": "http://example.com",
				},
			},
		},
		{
			name: "attack event with no data",
			input: &api.RunAttackResponse{
				EventType: "attack.completed",
				Timestamp: 1640000100,
				Message:   "Attack completed",
			},
			expected: AttackEvent{
				Type:      "attack.completed",
				Timestamp: time.Unix(1640000100, 0),
				Message:   "Attack completed",
				Severity:  "",
				Data:      nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProtoAttackEvent(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConvertProtoEvent tests the convertProtoEvent function.
func TestConvertProtoEvent(t *testing.T) {
	tests := []struct {
		name     string
		input    *api.SubscribeResponse
		expected Event
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: Event{},
		},
		{
			name: "complete event",
			input: &api.SubscribeResponse{
				EventType: "agent_registered",
				Timestamp: 1640000000,
				Source:    "registry",
				Data: api.MapToTypedMap(map[string]any{
					"agent": "test-agent",
				}),
			},
			expected: Event{
				Type:      "agent_registered",
				Source:    "registry",
				Timestamp: time.Unix(1640000000, 0),
				Data: map[string]interface{}{
					"agent": "test-agent",
				},
			},
		},
		{
			name: "event with no data",
			input: &api.SubscribeResponse{
				EventType: "system_ready",
				Timestamp: 1640000100,
				Source:    "daemon",
				Data:      nil,
			},
			expected: Event{
				Type:      "system_ready",
				Source:    "daemon",
				Timestamp: time.Unix(1640000100, 0),
				Data:      nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProtoEvent(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Mock DaemonServiceClient for testing client methods
type mockDaemonServiceClient struct {
	pingResponse        *api.PingResponse
	pingError           error
	statusResponse      *api.StatusResponse
	statusError         error
	listAgentsResponse  *api.ListAgentsResponse
	listAgentsError     error
	listToolsResponse   *api.ListToolsResponse
	listToolsError      error
	listPluginsResponse *api.ListPluginsResponse
	listPluginsError    error
}

func (m *mockDaemonServiceClient) Ping(ctx context.Context, req *api.PingRequest, opts ...grpc.CallOption) (*api.PingResponse, error) {
	return m.pingResponse, m.pingError
}

func (m *mockDaemonServiceClient) Status(ctx context.Context, req *api.StatusRequest, opts ...grpc.CallOption) (*api.StatusResponse, error) {
	return m.statusResponse, m.statusError
}

func (m *mockDaemonServiceClient) ListAgents(ctx context.Context, req *api.ListAgentsRequest, opts ...grpc.CallOption) (*api.ListAgentsResponse, error) {
	return m.listAgentsResponse, m.listAgentsError
}

func (m *mockDaemonServiceClient) ListTools(ctx context.Context, req *api.ListToolsRequest, opts ...grpc.CallOption) (*api.ListToolsResponse, error) {
	return m.listToolsResponse, m.listToolsError
}

func (m *mockDaemonServiceClient) ListPlugins(ctx context.Context, req *api.ListPluginsRequest, opts ...grpc.CallOption) (*api.ListPluginsResponse, error) {
	return m.listPluginsResponse, m.listPluginsError
}

// Stub implementations for other methods (not tested in this task)
func (m *mockDaemonServiceClient) Connect(ctx context.Context, req *api.ConnectRequest, opts ...grpc.CallOption) (*api.ConnectResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) RunMission(ctx context.Context, req *api.RunMissionRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[api.MissionEvent], error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) StopMission(ctx context.Context, req *api.StopMissionRequest, opts ...grpc.CallOption) (*api.StopMissionResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) ListMissions(ctx context.Context, req *api.ListMissionsRequest, opts ...grpc.CallOption) (*api.ListMissionsResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) GetAgentStatus(ctx context.Context, req *api.GetAgentStatusRequest, opts ...grpc.CallOption) (*api.GetAgentStatusResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) RunAttack(ctx context.Context, req *api.RunAttackRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[api.AttackEvent], error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) Subscribe(ctx context.Context, req *api.SubscribeRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[api.Event], error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) StartComponent(ctx context.Context, req *api.StartComponentRequest, opts ...grpc.CallOption) (*api.StartComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) StopComponent(ctx context.Context, req *api.StopComponentRequest, opts ...grpc.CallOption) (*api.StopComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) PauseMission(ctx context.Context, req *api.PauseMissionRequest, opts ...grpc.CallOption) (*api.PauseMissionResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) ResumeMission(ctx context.Context, req *api.ResumeMissionRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[api.MissionEvent], error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) GetMissionHistory(ctx context.Context, req *api.GetMissionHistoryRequest, opts ...grpc.CallOption) (*api.GetMissionHistoryResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) GetMissionCheckpoints(ctx context.Context, req *api.GetMissionCheckpointsRequest, opts ...grpc.CallOption) (*api.GetMissionCheckpointsResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) QueryPlugin(ctx context.Context, req *api.QueryPluginRequest, opts ...grpc.CallOption) (*api.QueryPluginResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) InstallComponent(ctx context.Context, req *api.InstallComponentRequest, opts ...grpc.CallOption) (*api.InstallComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) UninstallComponent(ctx context.Context, req *api.UninstallComponentRequest, opts ...grpc.CallOption) (*api.UninstallComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) UpdateComponent(ctx context.Context, req *api.UpdateComponentRequest, opts ...grpc.CallOption) (*api.UpdateComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) BuildComponent(ctx context.Context, req *api.BuildComponentRequest, opts ...grpc.CallOption) (*api.BuildComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) ShowComponent(ctx context.Context, req *api.ShowComponentRequest, opts ...grpc.CallOption) (*api.ShowComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) GetComponentLogs(ctx context.Context, req *api.GetComponentLogsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[api.LogEntry], error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) InstallAllComponent(ctx context.Context, req *api.InstallAllComponentRequest, opts ...grpc.CallOption) (*api.InstallAllComponentResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) EnsureDependenciesRunning(ctx context.Context, req *api.EnsureDependenciesRunningRequest, opts ...grpc.CallOption) (*api.EnsureDependenciesRunningResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) InstallMission(ctx context.Context, req *api.InstallMissionRequest, opts ...grpc.CallOption) (*api.InstallMissionResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) UninstallMission(ctx context.Context, req *api.UninstallMissionRequest, opts ...grpc.CallOption) (*api.UninstallMissionResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) UpdateMission(ctx context.Context, req *api.UpdateMissionRequest, opts ...grpc.CallOption) (*api.UpdateMissionResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) ListMissionDefinitions(ctx context.Context, req *api.ListMissionDefinitionsRequest, opts ...grpc.CallOption) (*api.ListMissionDefinitionsResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) ResolveMissionDependencies(ctx context.Context, req *api.ResolveMissionDependenciesRequest, opts ...grpc.CallOption) (*api.ResolveMissionDependenciesResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) ValidateMissionDependencies(ctx context.Context, req *api.ValidateMissionDependenciesRequest, opts ...grpc.CallOption) (*api.ValidateMissionDependenciesResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) CreateMission(ctx context.Context, req *api.CreateMissionRequest, opts ...grpc.CallOption) (*api.CreateMissionResponse, error) {
	return nil, nil
}
func (m *mockDaemonServiceClient) Shutdown(ctx context.Context, req *api.ShutdownRequest, opts ...grpc.CallOption) (*api.ShutdownResponse, error) {
	return &api.ShutdownResponse{Success: true, Message: "mock shutdown"}, nil
}

// TestClient_Ping tests the Ping method with mock client.
func TestClient_Ping(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *api.PingResponse
		mockError     error
		expectedError string
	}{
		{
			name: "successful ping",
			mockResponse: &api.PingResponse{
				Timestamp: time.Now().Unix(),
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "unavailable error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (connection unavailable)",
		},
		{
			name:          "deadline exceeded error",
			mockResponse:  nil,
			mockError:     status.Error(codes.DeadlineExceeded, "timeout"),
			expectedError: "daemon ping timeout",
		},
		{
			name:          "internal error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Internal, "server panic"),
			expectedError: "daemon ping failed: server panic",
		},
		{
			name:          "generic error",
			mockResponse:  nil,
			mockError:     assert.AnError,
			expectedError: "daemon ping failed:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonServiceClient{
				pingResponse: tt.mockResponse,
				pingError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			err := client.Ping(ctx)

			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_Status tests the Status method with mock client.
func TestClient_Status(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *api.StatusResponse
		mockError     error
		expectedError string
	}{
		{
			name: "successful status",
			mockResponse: &api.StatusResponse{
				Running:      true,
				Pid:          12345,
				StartTime:    time.Now().Unix(),
				Uptime:       "1h30m",
				GrpcAddress:  "localhost:50002",
				RegistryType: "embedded",
				AgentCount:   5,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "unavailable error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (is it running?)",
		},
		{
			name:          "deadline exceeded error",
			mockResponse:  nil,
			mockError:     status.Error(codes.DeadlineExceeded, "timeout"),
			expectedError: "daemon status request timeout",
		},
		{
			name:          "internal error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Internal, "database error"),
			expectedError: "failed to get daemon status: database error",
		},
		{
			name:          "generic error",
			mockResponse:  nil,
			mockError:     assert.AnError,
			expectedError: "failed to get daemon status:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonServiceClient{
				statusResponse: tt.mockResponse,
				statusError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.Status(ctx)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.mockResponse.Running, result.Running)
				assert.Equal(t, int(tt.mockResponse.Pid), result.PID)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_ListAgents tests the ListAgents method with mock client.
func TestClient_ListAgents(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *api.ListAgentsResponse
		mockError     error
		expectedCount int
		expectedError string
	}{
		{
			name: "successful list with agents",
			mockResponse: &api.ListAgentsResponse{
				Agents: []*api.AgentInfo{
					{
						Name:     "agent-1",
						Version:  "1.0.0",
						Endpoint: "localhost:50100",
						Health:   "healthy",
					},
					{
						Name:     "agent-2",
						Version:  "2.0.0",
						Endpoint: "localhost:50101",
						Health:   "healthy",
					},
				},
			},
			mockError:     nil,
			expectedCount: 2,
			expectedError: "",
		},
		{
			name: "successful list with empty results",
			mockResponse: &api.ListAgentsResponse{
				Agents: []*api.AgentInfo{},
			},
			mockError:     nil,
			expectedCount: 0,
			expectedError: "",
		},
		{
			name:          "unavailable error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedCount: 0,
			expectedError: "daemon not responding (is it running?)",
		},
		{
			name:          "deadline exceeded error",
			mockResponse:  nil,
			mockError:     status.Error(codes.DeadlineExceeded, "timeout"),
			expectedCount: 0,
			expectedError: "daemon request timeout while listing agents",
		},
		{
			name:          "internal error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Internal, "registry error"),
			expectedCount: 0,
			expectedError: "failed to list agents: registry error",
		},
		{
			name:          "not found error",
			mockResponse:  nil,
			mockError:     status.Error(codes.NotFound, "no agents found"),
			expectedCount: 0,
			expectedError: "failed to list agents: no agents found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonServiceClient{
				listAgentsResponse: tt.mockResponse,
				listAgentsError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.ListAgents(ctx)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result, tt.expectedCount)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_ListTools tests the ListTools method with mock client.
func TestClient_ListTools(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *api.ListToolsResponse
		mockError     error
		expectedCount int
		expectedError string
	}{
		{
			name: "successful list with tools",
			mockResponse: &api.ListToolsResponse{
				Tools: []*api.ToolInfo{
					{
						Name:        "nmap",
						Version:     "7.92",
						Description: "Network scanner",
						Endpoint:    "localhost:50200",
						Health:      "healthy",
					},
				},
			},
			mockError:     nil,
			expectedCount: 1,
			expectedError: "",
		},
		{
			name: "empty tools list",
			mockResponse: &api.ListToolsResponse{
				Tools: []*api.ToolInfo{},
			},
			mockError:     nil,
			expectedCount: 0,
			expectedError: "",
		},
		{
			name:          "unavailable error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedCount: 0,
			expectedError: "daemon not responding (is it running?)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonServiceClient{
				listToolsResponse: tt.mockResponse,
				listToolsError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.ListTools(ctx)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result, tt.expectedCount)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_ListPlugins tests the ListPlugins method with mock client.
func TestClient_ListPlugins(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *api.ListPluginsResponse
		mockError     error
		expectedCount int
		expectedError string
	}{
		{
			name: "successful list with plugins",
			mockResponse: &api.ListPluginsResponse{
				Plugins: []*api.PluginInfo{
					{
						Name:        "mitre-lookup",
						Version:     "1.0.0",
						Description: "MITRE ATT&CK lookup",
						Endpoint:    "localhost:50300",
						Health:      "healthy",
					},
				},
			},
			mockError:     nil,
			expectedCount: 1,
			expectedError: "",
		},
		{
			name: "empty plugins list",
			mockResponse: &api.ListPluginsResponse{
				Plugins: []*api.PluginInfo{},
			},
			mockError:     nil,
			expectedCount: 0,
			expectedError: "",
		},
		{
			name:          "unavailable error",
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedCount: 0,
			expectedError: "daemon not responding (is it running?)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonServiceClient{
				listPluginsResponse: tt.mockResponse,
				listPluginsError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.ListPlugins(ctx)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Len(t, result, tt.expectedCount)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// Keep existing tests for Connect and ConnectFromInfo
func TestConnect_InvalidAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Test empty address
	_, err := Connect(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestConnect_UnixSocketFormat(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		wantErr  bool
		errMatch string
	}{
		{
			name:     "unix scheme with absolute path",
			address:  "unix:///nonexistent/socket",
			wantErr:  true, // Connection will fail since socket doesn't exist
			errMatch: "failed to connect",
		},
		{
			name:     "absolute path without scheme",
			address:  "/nonexistent/socket",
			wantErr:  true,
			errMatch: "failed to connect",
		},
		{
			name:     "tcp address",
			address:  "localhost:50002",
			wantErr:  true, // No server listening
			errMatch: "failed to connect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			client, err := Connect(ctx, tt.address)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMatch != "" {
					assert.Contains(t, err.Error(), tt.errMatch)
				}
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				if client != nil {
					client.Close()
				}
			}
		})
	}
}

// ConnectFromInfo tests removed - function was deleted as part of K8s-native CLI migration

func TestClient_Close_Nil(t *testing.T) {
	client := &Client{conn: nil}
	err := client.Close()
	assert.NoError(t, err, "Close on nil connection should not error")
}

func TestConnectOrFail_NoDaemon(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// ConnectOrFail now uses env var or default address
	// Without a daemon running, it should fail to connect
	client, err := ConnectOrFail(ctx)

	assert.Error(t, err)
	assert.Nil(t, client)
	// Error should mention the daemon is not running or unreachable
	assert.Contains(t, err.Error(), "daemon")
}

// TestGetGibsonHome removed - function was deleted as part of K8s-native CLI migration
// Connection now uses GIBSON_DAEMON_ADDRESS env var or defaults to localhost:50002

// mockDaemonClientForComponents extends the mock with component management responses
type mockDaemonClientForComponents struct {
	mockDaemonServiceClient
	installResponse   *api.InstallComponentResponse
	installError      error
	uninstallResponse *api.UninstallComponentResponse
	uninstallError    error
	updateResponse    *api.UpdateComponentResponse
	updateError       error
	buildResponse     *api.BuildComponentResponse
	buildError        error
	showResponse      *api.ShowComponentResponse
	showError         error
}

func (m *mockDaemonClientForComponents) InstallComponent(ctx context.Context, req *api.InstallComponentRequest, opts ...grpc.CallOption) (*api.InstallComponentResponse, error) {
	return m.installResponse, m.installError
}

func (m *mockDaemonClientForComponents) UninstallComponent(ctx context.Context, req *api.UninstallComponentRequest, opts ...grpc.CallOption) (*api.UninstallComponentResponse, error) {
	return m.uninstallResponse, m.uninstallError
}

func (m *mockDaemonClientForComponents) UpdateComponent(ctx context.Context, req *api.UpdateComponentRequest, opts ...grpc.CallOption) (*api.UpdateComponentResponse, error) {
	return m.updateResponse, m.updateError
}

func (m *mockDaemonClientForComponents) BuildComponent(ctx context.Context, req *api.BuildComponentRequest, opts ...grpc.CallOption) (*api.BuildComponentResponse, error) {
	return m.buildResponse, m.buildError
}

func (m *mockDaemonClientForComponents) ShowComponent(ctx context.Context, req *api.ShowComponentRequest, opts ...grpc.CallOption) (*api.ShowComponentResponse, error) {
	return m.showResponse, m.showError
}

// TestClient_InstallAgent tests the InstallAgent method
func TestClient_InstallAgent(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		opts          InstallOptions
		mockResponse  *api.InstallComponentResponse
		mockError     error
		expectedError string
	}{
		{
			name: "successful install",
			url:  "https://github.com/zero-day-ai/test-agent",
			opts: InstallOptions{},
			mockResponse: &api.InstallComponentResponse{
				Success:     true,
				Name:        "test-agent",
				Version:     "1.0.0",
				RepoPath:    "/home/user/.gibson/components/agents/test-agent",
				BinPath:     "/home/user/.gibson/components/agents/test-agent/test-agent",
				BuildOutput: "Build successful",
				DurationMs:  5000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name: "install with branch",
			url:  "https://github.com/zero-day-ai/test-agent",
			opts: InstallOptions{Branch: "dev"},
			mockResponse: &api.InstallComponentResponse{
				Success:    true,
				Name:       "test-agent",
				Version:    "1.0.0-dev",
				RepoPath:   "/home/user/.gibson/components/agents/test-agent",
				DurationMs: 5000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "already exists error",
			url:           "https://github.com/zero-day-ai/test-agent",
			opts:          InstallOptions{},
			mockResponse:  nil,
			mockError:     status.Error(codes.AlreadyExists, "component already exists"),
			expectedError: "component already exists (use --force to reinstall)",
		},
		{
			name:          "not found error",
			url:           "https://github.com/zero-day-ai/nonexistent",
			opts:          InstallOptions{},
			mockResponse:  nil,
			mockError:     status.Error(codes.NotFound, "repository not found"),
			expectedError: "repository not found",
		},
		{
			name:          "daemon unavailable",
			url:           "https://github.com/zero-day-ai/test-agent",
			opts:          InstallOptions{},
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (is it running?)",
		},
		{
			name: "install failure response",
			url:  "https://github.com/zero-day-ai/test-agent",
			opts: InstallOptions{},
			mockResponse: &api.InstallComponentResponse{
				Success: false,
				Message: "build failed: compilation error",
			},
			mockError:     nil,
			expectedError: "failed to install component: build failed: compilation error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonClientForComponents{
				installResponse: tt.mockResponse,
				installError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.InstallAgent(ctx, tt.url, tt.opts)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.mockResponse.Name, result.Name)
				assert.Equal(t, tt.mockResponse.Version, result.Version)
				assert.Equal(t, "agent", result.Kind)
				assert.Equal(t, time.Duration(tt.mockResponse.DurationMs)*time.Millisecond, result.Duration)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_InstallTool tests the InstallTool method
func TestClient_InstallTool(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  *api.InstallComponentResponse
		mockError     error
		expectedError string
	}{
		{
			name: "successful tool install",
			mockResponse: &api.InstallComponentResponse{
				Success:    true,
				Name:       "nmap-tool",
				Version:    "1.0.0",
				RepoPath:   "/home/user/.gibson/components/tools/nmap-tool",
				DurationMs: 3000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "invalid argument error",
			mockResponse:  nil,
			mockError:     status.Error(codes.InvalidArgument, "invalid URL format"),
			expectedError: "invalid component URL or options: invalid URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonClientForComponents{
				installResponse: tt.mockResponse,
				installError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.InstallTool(ctx, "https://github.com/zero-day-ai/nmap-tool", InstallOptions{})

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, "tool", result.Kind)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_InstallPlugin tests the InstallPlugin method
func TestClient_InstallPlugin(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		installResponse: &api.InstallComponentResponse{
			Success:    true,
			Name:       "mitre-plugin",
			Version:    "2.0.0",
			RepoPath:   "/home/user/.gibson/components/plugins/mitre-plugin",
			DurationMs: 2000,
		},
		installError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	result, err := client.InstallPlugin(ctx, "https://github.com/zero-day-ai/mitre-plugin", InstallOptions{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "plugin", result.Kind)
	assert.Equal(t, "mitre-plugin", result.Name)
}

// TestClient_UninstallAgent tests the UninstallAgent method
func TestClient_UninstallAgent(t *testing.T) {
	tests := []struct {
		name          string
		agentName     string
		force         bool
		mockResponse  *api.UninstallComponentResponse
		mockError     error
		expectedError string
	}{
		{
			name:      "successful uninstall",
			agentName: "test-agent",
			force:     false,
			mockResponse: &api.UninstallComponentResponse{
				Success: true,
				Message: "Component uninstalled successfully",
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:      "force uninstall",
			agentName: "running-agent",
			force:     true,
			mockResponse: &api.UninstallComponentResponse{
				Success: true,
				Message: "Component force-uninstalled",
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "not found error",
			agentName:     "nonexistent-agent",
			force:         false,
			mockResponse:  nil,
			mockError:     status.Error(codes.NotFound, "component not found"),
			expectedError: "component 'nonexistent-agent' not found",
		},
		{
			name:          "failed precondition - component running",
			agentName:     "running-agent",
			force:         false,
			mockResponse:  nil,
			mockError:     status.Error(codes.FailedPrecondition, "component is running"),
			expectedError: "component 'running-agent' is running (stop it first or use --force)",
		},
		{
			name:          "daemon unavailable",
			agentName:     "test-agent",
			force:         false,
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (is it running?)",
		},
		{
			name:      "uninstall failure response",
			agentName: "test-agent",
			force:     false,
			mockResponse: &api.UninstallComponentResponse{
				Success: false,
				Message: "failed to remove files: permission denied",
			},
			mockError:     nil,
			expectedError: "failed to uninstall component: failed to remove files: permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonClientForComponents{
				uninstallResponse: tt.mockResponse,
				uninstallError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			err := client.UninstallAgent(ctx, tt.agentName, tt.force)

			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_UninstallTool tests the UninstallTool method
func TestClient_UninstallTool(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		uninstallResponse: &api.UninstallComponentResponse{
			Success: true,
			Message: "Tool uninstalled",
		},
		uninstallError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	err := client.UninstallTool(ctx, "nmap-tool", false)

	assert.NoError(t, err)
}

// TestClient_UninstallPlugin tests the UninstallPlugin method
func TestClient_UninstallPlugin(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		uninstallResponse: &api.UninstallComponentResponse{
			Success: true,
			Message: "Plugin uninstalled",
		},
		uninstallError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	err := client.UninstallPlugin(ctx, "mitre-plugin", false)

	assert.NoError(t, err)
}

// TestClient_UpdateAgent tests the UpdateAgent method
func TestClient_UpdateAgent(t *testing.T) {
	tests := []struct {
		name          string
		agentName     string
		opts          UpdateOptions
		mockResponse  *api.UpdateComponentResponse
		mockError     error
		expectedError string
	}{
		{
			name:      "successful update with changes",
			agentName: "test-agent",
			opts:      UpdateOptions{},
			mockResponse: &api.UpdateComponentResponse{
				Success:     true,
				Updated:     true,
				OldVersion:  "1.0.0",
				NewVersion:  "1.1.0",
				BuildOutput: "Build successful",
				DurationMs:  4000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:      "already up to date",
			agentName: "test-agent",
			opts:      UpdateOptions{},
			mockResponse: &api.UpdateComponentResponse{
				Success:     true,
				Updated:     false,
				OldVersion:  "1.0.0",
				NewVersion:  "1.0.0",
				BuildOutput: "",
				DurationMs:  100,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:      "update with restart",
			agentName: "test-agent",
			opts:      UpdateOptions{Restart: true},
			mockResponse: &api.UpdateComponentResponse{
				Success:     true,
				Updated:     true,
				OldVersion:  "1.0.0",
				NewVersion:  "1.1.0",
				BuildOutput: "Build and restart successful",
				DurationMs:  5000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "not found error",
			agentName:     "nonexistent-agent",
			opts:          UpdateOptions{},
			mockResponse:  nil,
			mockError:     status.Error(codes.NotFound, "component not found"),
			expectedError: "component 'nonexistent-agent' not found",
		},
		{
			name:          "daemon unavailable",
			agentName:     "test-agent",
			opts:          UpdateOptions{},
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (is it running?)",
		},
		{
			name:      "update failure response",
			agentName: "test-agent",
			opts:      UpdateOptions{},
			mockResponse: &api.UpdateComponentResponse{
				Success: false,
				Message: "git pull failed: network error",
			},
			mockError:     nil,
			expectedError: "failed to update component: git pull failed: network error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonClientForComponents{
				updateResponse: tt.mockResponse,
				updateError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.UpdateAgent(ctx, tt.agentName, tt.opts)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.mockResponse.Updated, result.Updated)
				assert.Equal(t, tt.mockResponse.OldVersion, result.OldVersion)
				assert.Equal(t, tt.mockResponse.NewVersion, result.NewVersion)
				assert.Equal(t, time.Duration(tt.mockResponse.DurationMs)*time.Millisecond, result.Duration)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_UpdateTool tests the UpdateTool method
func TestClient_UpdateTool(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		updateResponse: &api.UpdateComponentResponse{
			Success:    true,
			Updated:    true,
			OldVersion: "1.0.0",
			NewVersion: "1.1.0",
			DurationMs: 3000,
		},
		updateError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	result, err := client.UpdateTool(ctx, "nmap-tool", UpdateOptions{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Updated)
}

// TestClient_UpdatePlugin tests the UpdatePlugin method
func TestClient_UpdatePlugin(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		updateResponse: &api.UpdateComponentResponse{
			Success:    true,
			Updated:    false,
			OldVersion: "2.0.0",
			NewVersion: "2.0.0",
			DurationMs: 100,
		},
		updateError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	result, err := client.UpdatePlugin(ctx, "mitre-plugin", UpdateOptions{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Updated)
}

// TestClient_BuildAgent tests the BuildAgent method
func TestClient_BuildAgent(t *testing.T) {
	tests := []struct {
		name          string
		agentName     string
		mockResponse  *api.BuildComponentResponse
		mockError     error
		expectedError string
	}{
		{
			name:      "successful build",
			agentName: "test-agent",
			mockResponse: &api.BuildComponentResponse{
				Success:    true,
				Stdout:     "go build -o test-agent\nBuild complete",
				Stderr:     "",
				DurationMs: 3000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:      "build with warnings",
			agentName: "test-agent",
			mockResponse: &api.BuildComponentResponse{
				Success:    true,
				Stdout:     "go build -o test-agent\nBuild complete",
				Stderr:     "warning: unused variable",
				DurationMs: 3000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:      "build failure",
			agentName: "test-agent",
			mockResponse: &api.BuildComponentResponse{
				Success:    false,
				Stdout:     "go build -o test-agent",
				Stderr:     "compilation error: syntax error",
				DurationMs: 1000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "not found error",
			agentName:     "nonexistent-agent",
			mockResponse:  nil,
			mockError:     status.Error(codes.NotFound, "component not found"),
			expectedError: "component 'nonexistent-agent' not found",
		},
		{
			name:          "daemon unavailable",
			agentName:     "test-agent",
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (is it running?)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonClientForComponents{
				buildResponse: tt.mockResponse,
				buildError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.BuildAgent(ctx, tt.agentName)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.mockResponse.Success, result.Success)
				assert.Equal(t, tt.mockResponse.Stdout, result.Stdout)
				assert.Equal(t, tt.mockResponse.Stderr, result.Stderr)
				assert.Equal(t, time.Duration(tt.mockResponse.DurationMs)*time.Millisecond, result.Duration)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_BuildTool tests the BuildTool method
func TestClient_BuildTool(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		buildResponse: &api.BuildComponentResponse{
			Success:    true,
			Stdout:     "Build successful",
			Stderr:     "",
			DurationMs: 2000,
		},
		buildError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	result, err := client.BuildTool(ctx, "nmap-tool")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
}

// TestClient_BuildPlugin tests the BuildPlugin method
func TestClient_BuildPlugin(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		buildResponse: &api.BuildComponentResponse{
			Success:    true,
			Stdout:     "npm run build\nBuild complete",
			Stderr:     "",
			DurationMs: 5000,
		},
		buildError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	result, err := client.BuildPlugin(ctx, "mitre-plugin")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
}

// TestClient_ShowAgent tests the ShowAgent method
func TestClient_ShowAgent(t *testing.T) {
	tests := []struct {
		name          string
		agentName     string
		mockResponse  *api.ShowComponentResponse
		mockError     error
		expectedError string
	}{
		{
			name:      "successful show with running agent",
			agentName: "test-agent",
			mockResponse: &api.ShowComponentResponse{
				Success:      true,
				Name:         "test-agent",
				Version:      "1.0.0",
				Kind:         "agent",
				Status:       "running",
				Source:       "https://github.com/zero-day-ai/test-agent",
				RepoPath:     "/home/user/.gibson/components/agents/test-agent",
				BinPath:      "/home/user/.gibson/components/agents/test-agent/test-agent",
				Port:         50100,
				Pid:          12345,
				CreatedAt:    1640000000,
				UpdatedAt:    1640001000,
				StartedAt:    1640001000,
				StoppedAt:    0,
				ManifestInfo: `{"name":"test-agent","version":"1.0.0"}`,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:      "show stopped agent",
			agentName: "stopped-agent",
			mockResponse: &api.ShowComponentResponse{
				Success:   true,
				Name:      "stopped-agent",
				Version:   "1.0.0",
				Kind:      "agent",
				Status:    "stopped",
				Source:    "https://github.com/zero-day-ai/stopped-agent",
				RepoPath:  "/home/user/.gibson/components/agents/stopped-agent",
				BinPath:   "/home/user/.gibson/components/agents/stopped-agent/stopped-agent",
				Port:      0,
				Pid:       0,
				CreatedAt: 1640000000,
				UpdatedAt: 1640001000,
				StartedAt: 1640001000,
				StoppedAt: 1640002000,
			},
			mockError:     nil,
			expectedError: "",
		},
		{
			name:          "not found error",
			agentName:     "nonexistent-agent",
			mockResponse:  nil,
			mockError:     status.Error(codes.NotFound, "component not found"),
			expectedError: "component 'nonexistent-agent' not found",
		},
		{
			name:          "daemon unavailable",
			agentName:     "test-agent",
			mockResponse:  nil,
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (is it running?)",
		},
		{
			name:      "show failure response",
			agentName: "test-agent",
			mockResponse: &api.ShowComponentResponse{
				Success: false,
				Message: "failed to read component metadata",
			},
			mockError:     nil,
			expectedError: "failed to get component info: failed to read component metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDaemonClientForComponents{
				showResponse: tt.mockResponse,
				showError:    tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			result, err := client.ShowAgent(ctx, tt.agentName)

			if tt.expectedError == "" {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.mockResponse.Name, result.Name)
				assert.Equal(t, tt.mockResponse.Version, result.Version)
				assert.Equal(t, tt.mockResponse.Kind, result.Kind)
				assert.Equal(t, tt.mockResponse.Status, result.Status)
				assert.Equal(t, int(tt.mockResponse.Port), result.Port)
				assert.Equal(t, int(tt.mockResponse.Pid), result.PID)
				assert.Equal(t, time.Unix(tt.mockResponse.CreatedAt, 0), result.CreatedAt)
				assert.Equal(t, time.Unix(tt.mockResponse.UpdatedAt, 0), result.UpdatedAt)

				if tt.mockResponse.StartedAt > 0 {
					assert.NotNil(t, result.StartedAt)
					assert.Equal(t, time.Unix(tt.mockResponse.StartedAt, 0), *result.StartedAt)
				}
				if tt.mockResponse.StoppedAt > 0 {
					assert.NotNil(t, result.StoppedAt)
					assert.Equal(t, time.Unix(tt.mockResponse.StoppedAt, 0), *result.StoppedAt)
				}
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

// TestClient_ShowTool tests the ShowTool method
func TestClient_ShowTool(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		showResponse: &api.ShowComponentResponse{
			Success:   true,
			Name:      "nmap-tool",
			Version:   "1.0.0",
			Kind:      "tool",
			Status:    "ready",
			Source:    "https://github.com/zero-day-ai/nmap-tool",
			RepoPath:  "/home/user/.gibson/components/tools/nmap-tool",
			CreatedAt: 1640000000,
			UpdatedAt: 1640001000,
		},
		showError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	result, err := client.ShowTool(ctx, "nmap-tool")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "tool", result.Kind)
}

// TestClient_ShowPlugin tests the ShowPlugin method
func TestClient_ShowPlugin(t *testing.T) {
	mock := &mockDaemonClientForComponents{
		showResponse: &api.ShowComponentResponse{
			Success:   true,
			Name:      "mitre-plugin",
			Version:   "2.0.0",
			Kind:      "plugin",
			Status:    "running",
			Source:    "https://github.com/zero-day-ai/mitre-plugin",
			RepoPath:  "/home/user/.gibson/components/plugins/mitre-plugin",
			Port:      50300,
			Pid:       54321,
			CreatedAt: 1640000000,
			UpdatedAt: 1640001000,
			StartedAt: 1640001000,
		},
		showError: nil,
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	result, err := client.ShowPlugin(ctx, "mitre-plugin")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "plugin", result.Kind)
	assert.Equal(t, int(50300), result.Port)
}

// mockLogsClient extends the mock to handle GetComponentLogs
type mockLogsClient struct {
	mockDaemonClientForComponents
	logsError error
}

func (m *mockLogsClient) GetComponentLogs(ctx context.Context, req *api.GetComponentLogsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[api.LogEntry], error) {
	return nil, m.logsError
}

// TestClient_GetAgentLogs tests the GetAgentLogs method
func TestClient_GetAgentLogs(t *testing.T) {
	// Note: GetComponentLogs returns a streaming channel, so we primarily test error cases
	// Full streaming tests would require a more complex mock with stream implementation
	tests := []struct {
		name          string
		agentName     string
		opts          LogsOptions
		mockError     error
		expectedError string
	}{
		{
			name:          "not found error",
			agentName:     "nonexistent-agent",
			opts:          LogsOptions{Follow: false, Lines: 50},
			mockError:     status.Error(codes.NotFound, "component not found"),
			expectedError: "component 'nonexistent-agent' not found or no logs available",
		},
		{
			name:          "daemon unavailable",
			agentName:     "test-agent",
			opts:          LogsOptions{Follow: false, Lines: 50},
			mockError:     status.Error(codes.Unavailable, "connection refused"),
			expectedError: "daemon not responding (is it running?)",
		},
		{
			name:          "invalid argument error",
			agentName:     "test-agent",
			opts:          LogsOptions{Follow: false, Lines: -1},
			mockError:     status.Error(codes.InvalidArgument, "invalid lines parameter"),
			expectedError: "invalid component kind or name: invalid lines parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockLogsClient{
				logsError: tt.mockError,
			}

			client := &Client{
				daemon: mock,
			}

			ctx := context.Background()
			_, err := client.GetAgentLogs(ctx, tt.agentName, tt.opts)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// TestClient_GetToolLogs tests the GetToolLogs method
func TestClient_GetToolLogs(t *testing.T) {
	mock := &mockLogsClient{
		logsError: status.Error(codes.NotFound, "tool not found"),
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	_, err := client.GetToolLogs(ctx, "nmap-tool", LogsOptions{Lines: 100})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestClient_GetPluginLogs tests the GetPluginLogs method
func TestClient_GetPluginLogs(t *testing.T) {
	mock := &mockLogsClient{
		logsError: status.Error(codes.Unavailable, "daemon not available"),
	}

	client := &Client{
		daemon: mock,
	}

	ctx := context.Background()
	_, err := client.GetPluginLogs(ctx, "mitre-plugin", LogsOptions{Follow: true})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "daemon not responding")
}
