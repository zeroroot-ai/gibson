//go:build integration

package harness

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/memory"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/serve"
	sdktypes "github.com/zeroroot-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	protobuf "google.golang.org/protobuf/proto"
)

// mockIntegrationHarness is a minimal implementation of AgentHarness for testing callbacks.
// It implements only the methods needed for the integration test (Memory access).
type mockIntegrationHarness struct {
	memory           memory.MemoryStore
	logger           *slog.Logger
	tracer           trace.Tracer
	toolProtoOutputs map[string]protobuf.Message // Proto outputs by tool name
}

// Memory returns the memory store
func (m *mockIntegrationHarness) Memory() memory.MemoryStore {
	return m.memory
}

// Logger returns the logger
func (m *mockIntegrationHarness) Logger() *slog.Logger {
	return m.logger
}

// Tracer returns the tracer
func (m *mockIntegrationHarness) Tracer() trace.Tracer {
	return m.tracer
}

// Unimplemented methods required by AgentHarness interface
func (m *mockIntegrationHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, fmt.Errorf("Complete not implemented in mock harness")
}

func (m *mockIntegrationHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, fmt.Errorf("CompleteWithTools not implemented in mock harness")
}

func (m *mockIntegrationHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	return nil, fmt.Errorf("Stream not implemented in mock harness")
}

func (m *mockIntegrationHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	return nil, fmt.Errorf("CompleteStructuredAny not implemented in mock harness")
}

func (m *mockIntegrationHarness) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	return nil, fmt.Errorf("CompleteStructuredAnyWithUsage not implemented in mock harness")
}

func (m *mockIntegrationHarness) CallToolProto(ctx context.Context, name string, request protobuf.Message, response protobuf.Message) error {
	// If a proto output is set for this tool, copy it to the response
	if protoOut, ok := m.toolProtoOutputs[name]; ok {
		// Use protobuf.Merge to copy fields from the mock output to the response
		protobuf.Merge(response, protoOut)
		return nil
	}
	return fmt.Errorf("CallToolProto not configured for tool: %s", name)
}

func (m *mockIntegrationHarness) CallToolProtoStream(ctx context.Context, name string, request protobuf.Message, response protobuf.Message, callback sdkagent.ToolStreamCallback) error {
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

func (m *mockIntegrationHarness) ListTools() []ToolDescriptor {
	return nil
}

func (m *mockIntegrationHarness) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	return nil, fmt.Errorf("GetToolDescriptor not implemented in mock harness")
}

func (m *mockIntegrationHarness) QueryPlugin(ctx context.Context, componentName string, method string, params map[string]any) (any, error) {
	return nil, fmt.Errorf("QueryPlugin not implemented in mock harness")
}

func (m *mockIntegrationHarness) ListPlugins() []PluginDescriptor {
	return nil
}

func (m *mockIntegrationHarness) DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error) {
	return agent.Result{}, fmt.Errorf("DelegateToAgent not implemented in mock harness")
}

func (m *mockIntegrationHarness) ListAgents() []AgentDescriptor {
	return nil
}

func (m *mockIntegrationHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	return fmt.Errorf("SubmitFinding not implemented in mock harness")
}

func (m *mockIntegrationHarness) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("GetFindings not implemented in mock harness")
}

func (m *mockIntegrationHarness) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("GetAllRunFindings not implemented in mock harness")
}

func (m *mockIntegrationHarness) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	return nil, fmt.Errorf("GetMissionRunHistory not implemented in mock harness")
}

func (m *mockIntegrationHarness) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("GetPreviousRunFindings not implemented in mock harness")
}

func (m *mockIntegrationHarness) Mission() MissionContext {
	return MissionContext{}
}

func (m *mockIntegrationHarness) MissionID() types.ID {
	return types.ID("")
}

func (m *mockIntegrationHarness) MissionExecutionContext() MissionExecutionContextSDK {
	return MissionExecutionContextSDK{}
}

func (m *mockIntegrationHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return make(map[string]*sdktypes.Capabilities), nil
}

func (m *mockIntegrationHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return nil, fmt.Errorf("GetToolCapabilities not implemented in mock harness")
}

func (m *mockIntegrationHarness) Target() TargetInfo {
	return TargetInfo{}
}

func (m *mockIntegrationHarness) Metrics() MetricsRecorder {
	return nil
}

func (m *mockIntegrationHarness) TokenUsage() *llm.TokenTracker {
	return nil
}

// TestCallbackIntegration tests the full callback flow from agent to harness.
// It verifies that:
// 1. CallbackServer can start on a random available port
// 2. Harness registration works correctly
// 3. SDK CallbackClient can connect to the server
// 4. Memory operations (Set/Get) work through the callback mechanism
// 5. Server and client cleanup properly
func TestCallbackIntegration(t *testing.T) {
	// Skip if we can't bind to loopback (e.g., in restricted environments)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Cannot bind to loopback address: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Create logger for testing
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Step 1: Create registry and start CallbackServer with registry support
	registry := NewCallbackHarnessRegistry()
	server := NewCallbackServerWithRegistry(logger, port, registry)
	require.NotNil(t, server, "CallbackServer should be created")

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Ensure we stop the server at the end
	defer func() {
		cancel()
		server.Stop()
		// Wait for server to finish
		select {
		case <-serverErrCh:
		case <-time.After(2 * time.Second):
			t.Log("Server didn't stop gracefully within timeout")
		}
	}()

	// Step 2: Create mock harness with working memory
	workingMem := memory.NewWorkingMemory(10000) // 10k token budget
	mockMem := &mockMemoryStore{working: workingMem}
	harness := &mockIntegrationHarness{
		memory:           mockMem,
		logger:           logger,
		tracer:           noop.NewTracerProvider().Tracer("test"),
		toolProtoOutputs: make(map[string]protobuf.Message),
	}

	// Step 3: Register harness with mission ID and agent name (via registry)
	taskID := "integration-test-task-123"
	missionID := "integration-test-mission-456"
	agentName := "test-agent"
	registryKey := registry.Register(missionID, agentName, harness)
	defer registry.Unregister(registryKey)

	t.Logf("Registered harness: mission_id=%s agent_name=%s key=%s", missionID, agentName, registryKey)

	// Step 4: Create SDK CallbackClient and connect
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	client, err := serve.NewCallbackClient(endpoint)
	require.NoError(t, err, "CallbackClient should be created without error")
	require.NotNil(t, client, "CallbackClient should not be nil")

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connectCancel()

	err = client.Connect(connectCtx)
	require.NoError(t, err, "CallbackClient should connect successfully")
	defer client.Close()

	// Step 5: Set task context on the callback client (including mission ID)
	client.SetFullContext(serve.TaskContextParams{
		TaskID:    taskID,
		AgentName: agentName,
		MissionID: missionID,
		TraceID:   "trace-123",
		SpanID:    "span-456",
	})

	// Step 6: Test MemorySet callback
	testKey := "test-key"
	testValue := "test-value-123"

	setCtx, setCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer setCancel()

	setReq := &harnesspb.MemorySetRequest{
		Key:   testKey,
		Value: serve.ToTypedValue(testValue),
	}

	setResp, err := client.MemorySet(setCtx, setReq)
	require.NoError(t, err, "MemorySet callback should succeed")
	require.NotNil(t, setResp, "MemorySet response should not be nil")
	assert.Nil(t, setResp.Error, "MemorySet should not return an error")

	// Step 7: Verify the value was actually set in the mock harness
	storedValue, found := workingMem.Get(testKey)
	assert.True(t, found, "Value should be found in working memory")
	assert.Equal(t, testValue, storedValue, "Stored value should match what was set")

	// Step 8: Test MemoryGet callback
	getCtx, getCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer getCancel()

	getReq := &harnesspb.MemoryGetRequest{
		Key: testKey,
	}

	getResp, err := client.MemoryGet(getCtx, getReq)
	require.NoError(t, err, "MemoryGet callback should succeed")
	require.NotNil(t, getResp, "MemoryGet response should not be nil")
	assert.True(t, getResp.Found, "MemoryGet should indicate value was found")
	// The value is stored as a TypedValue - check string value
	require.NotNil(t, getResp.Value, "MemoryGet response value should not be nil")
	assert.Equal(t, testValue, getResp.Value.GetStringValue(), "Retrieved value should match what was set")

	// Step 9: Test MemoryGet for non-existent key
	getNonExistentCtx, getNonExistentCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer getNonExistentCancel()

	getNonExistentReq := &harnesspb.MemoryGetRequest{
		Key: "non-existent-key",
	}

	getNonExistentResp, err := client.MemoryGet(getNonExistentCtx, getNonExistentReq)
	require.NoError(t, err, "MemoryGet for non-existent key should not error")
	require.NotNil(t, getNonExistentResp, "Response should not be nil")
	assert.False(t, getNonExistentResp.Found, "Non-existent key should not be found")

	t.Log("Integration test completed successfully")
}

// mockMemoryStore implements the MemoryStore interface for testing
type mockMemoryStore struct {
	working  memory.WorkingMemory
	mission  memory.MissionMemory
	longTerm memory.LongTermMemory
}

func (m *mockMemoryStore) Working() memory.WorkingMemory {
	return m.working
}

func (m *mockMemoryStore) Mission() memory.MissionMemory {
	return m.mission
}

func (m *mockMemoryStore) LongTerm() memory.LongTermMemory {
	return m.longTerm
}

// TestMissionManagementCallbackIntegration tests the mission management callbacks.
// This verifies that mission-related RPC calls flow correctly through the callback system,
// even when they return "not yet implemented" errors.
func TestMissionManagementCallbackIntegration(t *testing.T) {
	// Skip if we can't bind to loopback
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Cannot bind to loopback address: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create registry and start CallbackServer
	registry := NewCallbackHarnessRegistry()
	server := NewCallbackServerWithRegistry(logger, port, registry)
	require.NotNil(t, server, "CallbackServer should be created")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	defer func() {
		cancel()
		server.Stop()
		select {
		case <-serverErrCh:
		case <-time.After(2 * time.Second):
			t.Log("Server didn't stop gracefully within timeout")
		}
	}()

	// Create mock harness
	workingMem := memory.NewWorkingMemory(10000)
	mockMem := &mockMemoryStore{working: workingMem}
	harness := &mockIntegrationHarness{
		memory:           mockMem,
		logger:           logger,
		tracer:           noop.NewTracerProvider().Tracer("test"),
		toolProtoOutputs: make(map[string]protobuf.Message),
	}

	// Register harness
	missionID := "mission-test-123"
	agentName := "test-agent"
	registryKey := registry.Register(missionID, agentName, harness)
	defer registry.Unregister(registryKey)

	// Create SDK CallbackClient and connect
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	client, err := serve.NewCallbackClient(endpoint)
	require.NoError(t, err)

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connectCancel()

	err = client.Connect(connectCtx)
	require.NoError(t, err)
	defer client.Close()

	// Set task context
	client.SetFullContext(serve.TaskContextParams{
		TaskID:    "task-123",
		AgentName: agentName,
		MissionID: missionID,
		TraceID:   "trace-123",
		SpanID:    "span-456",
	})

	// Test CreateMission callback
	t.Run("CreateMission callback flows correctly", func(t *testing.T) {
		createCtx, createCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer createCancel()

		createReq := &harnesspb.CreateMissionRequest{
			TargetId:              "target-456",
			Name:                  "sub-mission-test",
			MissionDefinitionJson: []byte(`{"name": "test-mission"}`),
		}

		createResp, err := client.CreateMission(createCtx, createReq)
		require.NoError(t, err, "CreateMission RPC should complete without transport error")
		require.NotNil(t, createResp, "CreateMission response should not be nil")
		// Currently returns "not yet implemented" error
		if createResp.Error != nil {
			assert.Contains(t, createResp.Error.Message, "not yet implemented")
		}
	})

	// Test GetMissionStatus callback
	t.Run("GetMissionStatus callback flows correctly", func(t *testing.T) {
		statusCtx, statusCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer statusCancel()

		statusReq := &harnesspb.GetMissionStatusRequest{
			MissionId: "target-mission-789",
		}

		statusResp, err := client.GetMissionStatus(statusCtx, statusReq)
		require.NoError(t, err, "GetMissionStatus RPC should complete without transport error")
		require.NotNil(t, statusResp, "GetMissionStatus response should not be nil")
		if statusResp.Error != nil {
			assert.Contains(t, statusResp.Error.Message, "not yet implemented")
		}
	})

	// Test ListMissions callback
	t.Run("ListMissions callback flows correctly", func(t *testing.T) {
		listCtx, listCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer listCancel()

		listReq := &harnesspb.ListMissionsRequest{}

		listResp, err := client.ListMissions(listCtx, listReq)
		require.NoError(t, err, "ListMissions RPC should complete without transport error")
		require.NotNil(t, listResp, "ListMissions response should not be nil")
		if listResp.Error != nil {
			assert.Contains(t, listResp.Error.Message, "not yet implemented")
		}
	})

	// Test CancelMission callback
	t.Run("CancelMission callback flows correctly", func(t *testing.T) {
		cancelCtx, cancelOpCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelOpCancel()

		cancelReq := &harnesspb.CancelMissionRequest{
			MissionId: "mission-to-cancel",
		}

		cancelResp, err := client.CancelMission(cancelCtx, cancelReq)
		require.NoError(t, err, "CancelMission RPC should complete without transport error")
		require.NotNil(t, cancelResp, "CancelMission response should not be nil")
		if cancelResp.Error != nil {
			assert.Contains(t, cancelResp.Error.Message, "not yet implemented")
		}
	})

	t.Log("Mission management integration test completed successfully")
}
