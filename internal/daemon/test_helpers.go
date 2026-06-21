package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/mission"
	"github.com/zeroroot-ai/gibson/internal/tool"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	sdktypes "github.com/zeroroot-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// mockComponentDiscovery is a mock implementation of component.ComponentDiscovery for testing.
type mockComponentDiscovery struct {
	agents          []component.AgentInfo
	tools           []component.ToolInfo
	plugins         []component.PluginInfo
	listAgentsFunc  func(ctx context.Context) ([]component.AgentInfo, error)
	listToolsFunc   func(ctx context.Context) ([]component.ToolInfo, error)
	listPluginsFunc func(ctx context.Context) ([]component.PluginInfo, error)
}

func (m *mockComponentDiscovery) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	if m.listAgentsFunc != nil {
		return m.listAgentsFunc(ctx)
	}
	if m.agents != nil {
		return m.agents, nil
	}
	return []component.AgentInfo{}, nil
}

func (m *mockComponentDiscovery) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	if m.listToolsFunc != nil {
		return m.listToolsFunc(ctx)
	}
	if m.tools != nil {
		return m.tools, nil
	}
	return []component.ToolInfo{}, nil
}

func (m *mockComponentDiscovery) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	if m.listPluginsFunc != nil {
		return m.listPluginsFunc(ctx)
	}
	if m.plugins != nil {
		return m.plugins, nil
	}
	return []component.PluginInfo{}, nil
}

// Stub implementations for other ComponentDiscovery interface methods
func (m *mockComponentDiscovery) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

// DiscoverPlugin was removed from component.ComponentDiscovery in plugin-runtime
// Spec 2 Phase 7; plugin invocation now goes through PluginInvokeService.

func (m *mockComponentDiscovery) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, fmt.Errorf("not implemented in mock")
}

// mockMissionStore is a mock implementation of mission.MissionStore for testing.
type mockMissionStore struct {
	missions       map[types.ID]*mission.Mission
	saveFunc       func(ctx context.Context, m *mission.Mission) error
	updateFunc     func(ctx context.Context, m *mission.Mission) error
	getFunc        func(ctx context.Context, id types.ID) (*mission.Mission, error)
	listFunc       func(ctx context.Context, filter *mission.MissionFilter) ([]*mission.Mission, error)
	deleteFunc     func(ctx context.Context, id types.ID) error
	setStatusFunc  func(ctx context.Context, id types.ID, status mission.MissionStatus) error
	findByNameFunc func(ctx context.Context, name string) (*mission.Mission, error)
}

func (m *mockMissionStore) Save(ctx context.Context, missionRecord *mission.Mission) error {
	if m.saveFunc != nil {
		return m.saveFunc(ctx, missionRecord)
	}
	if m.missions == nil {
		m.missions = make(map[types.ID]*mission.Mission)
	}
	m.missions[missionRecord.ID] = missionRecord
	return nil
}

func (m *mockMissionStore) Update(ctx context.Context, missionRecord *mission.Mission) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, missionRecord)
	}
	if m.missions == nil {
		m.missions = make(map[types.ID]*mission.Mission)
	}
	m.missions[missionRecord.ID] = missionRecord
	return nil
}

func (m *mockMissionStore) Get(ctx context.Context, id types.ID) (*mission.Mission, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, id)
	}
	if missionRecord, ok := m.missions[id]; ok {
		return missionRecord, nil
	}
	return nil, mission.NewNotFoundError(id.String())
}

func (m *mockMissionStore) List(ctx context.Context, filter *mission.MissionFilter) ([]*mission.Mission, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, filter)
	}
	var result []*mission.Mission
	for _, mission := range m.missions {
		result = append(result, mission)
	}
	return result, nil
}

func (m *mockMissionStore) Delete(ctx context.Context, id types.ID) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}
	delete(m.missions, id)
	return nil
}

func (m *mockMissionStore) UpdateStatus(ctx context.Context, id types.ID, status mission.MissionStatus) error {
	if m.setStatusFunc != nil {
		return m.setStatusFunc(ctx, id, status)
	}
	if missionRecord, ok := m.missions[id]; ok {
		missionRecord.Status = status
		return nil
	}
	return mission.NewNotFoundError(id.String())
}

func (m *mockMissionStore) GetByName(ctx context.Context, name string) (*mission.Mission, error) {
	if m.findByNameFunc != nil {
		return m.findByNameFunc(ctx, name)
	}
	for _, missionRecord := range m.missions {
		if missionRecord.Name == name {
			return missionRecord, nil
		}
	}
	return nil, mission.NewNotFoundError(name)
}

func (m *mockMissionStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	return nil
}

func (m *mockMissionStore) GetByTarget(ctx context.Context, targetID types.ID) ([]*mission.Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) GetActive(ctx context.Context) ([]*mission.Mission, error) {
	var result []*mission.Mission
	for _, rec := range m.missions {
		if rec.Status == mission.MissionStatusRunning || rec.Status == mission.MissionStatusPaused {
			result = append(result, rec)
		}
	}
	return result, nil
}

func (m *mockMissionStore) SaveCheckpoint(ctx context.Context, missionID types.ID, checkpoint *mission.MissionCheckpoint) error {
	return nil
}

func (m *mockMissionStore) Count(ctx context.Context, filter *mission.MissionFilter) (int, error) {
	return len(m.missions), nil
}

func (m *mockMissionStore) GetByNameAndStatus(ctx context.Context, name string, status mission.MissionStatus) (*mission.Mission, error) {
	for _, rec := range m.missions {
		if rec.Name == name && rec.Status == status {
			return rec, nil
		}
	}
	return nil, mission.NewNotFoundError(name)
}

func (m *mockMissionStore) ListByName(ctx context.Context, name string, limit int) ([]*mission.Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) GetLatestByName(ctx context.Context, name string) (*mission.Mission, error) {
	return nil, mission.NewNotFoundError(name)
}

func (m *mockMissionStore) IncrementRunNumber(ctx context.Context, name string) (int, error) {
	return 1, nil
}

func (m *mockMissionStore) FindOrCreateByName(ctx context.Context, mis *mission.Mission) (*mission.Mission, bool, error) {
	for _, rec := range m.missions {
		if rec.Name == mis.Name {
			return rec, false, nil
		}
	}
	if m.missions == nil {
		m.missions = make(map[types.ID]*mission.Mission)
	}
	m.missions[mis.ID] = mis
	return mis, true, nil
}

func (m *mockMissionStore) CreateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	return nil
}

func (m *mockMissionStore) GetDefinition(ctx context.Context, name string) (*missionv1.MissionDefinition, error) {
	return nil, nil
}

func (m *mockMissionStore) ListDefinitions(ctx context.Context) ([]*missionv1.MissionDefinition, error) {
	return nil, nil
}

func (m *mockMissionStore) UpdateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	return nil
}

func (m *mockMissionStore) DeleteDefinition(ctx context.Context, name string) error {
	return nil
}

// mockHarnessFactory is a mock implementation of harness.HarnessFactoryInterface for testing.
type mockHarnessFactory struct {
	createFunc func(agentName string, missionCtx harness.MissionContext, targetInfo harness.TargetInfo) (harness.AgentHarness, error)
}

func (m *mockHarnessFactory) Create(agentName string, missionCtx harness.MissionContext, targetInfo harness.TargetInfo) (harness.AgentHarness, error) {
	if m.createFunc != nil {
		return m.createFunc(agentName, missionCtx, targetInfo)
	}
	// Return a minimal mock harness
	return &mockAgentHarness{}, nil
}

// mockAgentHarness is a minimal mock implementation of harness.AgentHarness for testing.
type mockAgentHarness struct {
	toolProtoOutputs map[string]proto.Message
	toolErrors       map[string]error
}

func (m *mockAgentHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...harness.CompletionOption) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{}, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...harness.CompletionOption) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{}, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...harness.CompletionOption) (<-chan llm.StreamChunk, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...harness.CompletionOption) (any, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...harness.CompletionOption) (*harness.StructuredCompletionResult, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	if err, ok := m.toolErrors[name]; ok {
		return err
	}
	if protoOut, ok := m.toolProtoOutputs[name]; ok {
		proto.Merge(response, protoOut)
	}
	return nil
}

func (m *mockAgentHarness) CallToolProtoStream(ctx context.Context, name string, request, response proto.Message, callback sdkagent.ToolStreamCallback) error {
	if err := m.CallToolProto(ctx, name, request, response); err != nil {
		if callback != nil {
			callback.OnError(err, true)
		}
		return err
	}
	if callback != nil {
		callback.OnPartial(response, false)
	}
	return nil
}

func (m *mockAgentHarness) ListTools() []harness.ToolDescriptor {
	return nil
}

func (m *mockAgentHarness) GetToolDescriptor(ctx context.Context, name string) (*harness.ToolDescriptor, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) ListPlugins() []harness.PluginDescriptor {
	return nil
}

func (m *mockAgentHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	return agent.Result{}, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) ListAgents() []harness.AgentDescriptor {
	return nil
}

func (m *mockAgentHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	return fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) GetFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockAgentHarness) Mission() harness.MissionContext {
	return harness.MissionContext{}
}

func (m *mockAgentHarness) Workspace() workspace.Workspace {
	return nil
}

func (m *mockAgentHarness) Workspaces() map[string]workspace.Workspace {
	return map[string]workspace.Workspace{}
}

func (m *mockAgentHarness) MissionID() types.ID {
	return types.ID("")
}

func (m *mockAgentHarness) Target() harness.TargetInfo {
	return harness.TargetInfo{}
}

func (m *mockAgentHarness) Tracer() trace.Tracer {
	return nil
}

func (m *mockAgentHarness) Logger() *slog.Logger {
	return slog.Default()
}

func (m *mockAgentHarness) Metrics() harness.MetricsRecorder {
	return &mockMetricsRecorder{}
}

func (m *mockAgentHarness) TokenUsage() *llm.TokenTracker {
	return nil
}

func (m *mockAgentHarness) MissionExecutionContext() harness.MissionExecutionContextSDK {
	return harness.MissionExecutionContextSDK{}
}

func (m *mockAgentHarness) GetMissionRunHistory(ctx context.Context) ([]harness.MissionRunSummarySDK, error) {
	return nil, nil
}

func (m *mockAgentHarness) GetPreviousRunFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}

func (m *mockAgentHarness) GetAllRunFindings(ctx context.Context, filter harness.FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}

func (m *mockAgentHarness) Checkpoint() harness.CheckpointAccess {
	return harness.NewHarnessCheckpointMethods(nil, "", "", 0)
}

// mockMetricsRecorder is a minimal mock implementation for testing.
type mockMetricsRecorder struct{}

func (m *mockMetricsRecorder) RecordCounter(name string, value int64, labels map[string]string)     {}
func (m *mockMetricsRecorder) RecordGauge(name string, value float64, labels map[string]string)     {}
func (m *mockMetricsRecorder) RecordHistogram(name string, value float64, labels map[string]string) {}
func (m *mockMetricsRecorder) RecordDuration(name string, d any, labels map[string]string)          {}
