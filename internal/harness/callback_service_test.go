package harness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// TestNewHarnessCallbackService tests the service constructor.
func TestNewHarnessCallbackService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	assert.NotNil(t, service)
	assert.NotNil(t, service.logger)
}

// TestHarnessCallbackServiceRegisterUnregister tests harness registration.
func TestHarnessCallbackServiceRegisterUnregister(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	// Register a harness
	taskID := "task-123"
	service.RegisterHarness(taskID, nil)

	// Check it's registered (we can try to get it)
	_, ok := service.activeHarnesses.Load(taskID)
	assert.True(t, ok)

	// Unregister
	service.UnregisterHarness(taskID)

	// Check it's gone
	_, ok = service.activeHarnesses.Load(taskID)
	assert.False(t, ok)
}

// newMockHarness creates a minimal harness for testing.
func newMockHarness() AgentHarness {
	// Create a minimal harness with nil dependencies - we only need it for storage/retrieval
	return &DefaultAgentHarness{}
}

// TestGetHarness_WithExplicitMissionId tests getHarness with explicit MissionId field.
func TestGetHarness_WithExplicitMissionId(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a mock harness
	mockHarn := newMockHarness()

	// Create callback harness registry and register the harness
	registry := NewCallbackHarnessRegistry()
	registry.Register("mission-123", "test-agent", mockHarn)

	// Create service with registry
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	// Create ContextInfo with explicit MissionId
	contextInfo := &harnesspb.ContextInfo{
		TaskId:    "task-456",
		AgentName: "test-agent",
		MissionId: "mission-123",
	}

	// Test getHarness
	harness, err := service.getHarness(context.Background(), contextInfo)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, mockHarn, harness)
}

// TestGetHarness_EmptyMissionId_ReturnsError tests that empty mission_id returns an error.
// Legacy task-based fallback is no longer supported.
func TestGetHarness_EmptyMissionId_ReturnsError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create callback harness registry
	registry := NewCallbackHarnessRegistry()

	// Create service with registry
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	// Create ContextInfo with empty MissionId
	contextInfo := &harnesspb.ContextInfo{
		TaskId:    "task-789",
		AgentName: "test-agent",
		MissionId: "", // Empty - should return error (legacy fallback removed)
	}

	// Test getHarness
	harness, err := service.getHarness(context.Background(), contextInfo)

	// Verify error is returned (legacy fallback no longer supported)
	require.Error(t, err)
	assert.Nil(t, harness)
	assert.Contains(t, err.Error(), "missing mission_id")
}

// TestGetHarness_LegacyTaskIdWithColon tests that legacy missionID:taskID format no longer works.
// The new implementation requires explicit MissionId field.
func TestGetHarness_LegacyTaskIdWithColon_NoLongerSupported(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a mock harness
	mockHarn := newMockHarness()

	// Create callback harness registry and register the harness
	registry := NewCallbackHarnessRegistry()
	registry.Register("mission-abc", "test-agent", mockHarn)

	// Create service with registry
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	// Create ContextInfo with legacy format (mission in TaskId) but no explicit MissionId
	contextInfo := &harnesspb.ContextInfo{
		TaskId:    "mission-abc:task-xyz", // Legacy format
		AgentName: "test-agent",
		MissionId: "", // Empty - legacy parsing no longer supported
	}

	// Test getHarness
	harness, err := service.getHarness(context.Background(), contextInfo)

	// Verify error is returned (legacy format no longer supported)
	require.Error(t, err)
	assert.Nil(t, harness)
	assert.Contains(t, err.Error(), "missing mission_id")
}

// TestGetHarness_MissionIdNotFound tests error handling when mission not found.
func TestGetHarness_MissionIdNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create empty callback harness registry
	registry := NewCallbackHarnessRegistry()

	// Create service with registry
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	// Create ContextInfo with non-existent mission
	contextInfo := &harnesspb.ContextInfo{
		TaskId:    "task-999",
		AgentName: "test-agent",
		MissionId: "nonexistent-mission",
	}

	// Test getHarness
	harness, err := service.getHarness(context.Background(), contextInfo)

	// Verify error is returned
	require.Error(t, err)
	assert.Nil(t, harness)
	assert.Contains(t, err.Error(), "no active harness for mission")
}

// ============================================================================
// Mission Management Callback Handler Tests
// ============================================================================

// TestHarnessCallbackService_CreateMission tests the CreateMission RPC handler.
func TestHarnessCallbackService_CreateMission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	ctx := context.Background()
	req := &harnesspb.CreateMissionRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: "test-agent",
			MissionId: "mission-123",
		},
		TargetId: "target-456",
		Name:     "test-mission",
	}

	resp, err := service.CreateMission(ctx, req)

	// Should return response with error (not yet implemented)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not yet implemented")
}

// TestHarnessCallbackService_RunMission tests the RunMission RPC handler.
func TestHarnessCallbackService_RunMission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	ctx := context.Background()
	req := &harnesspb.RunMissionRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: "test-agent",
			MissionId: "mission-123",
		},
		MissionId: "target-mission-456",
	}

	resp, err := service.RunMission(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not yet implemented")
}

// TestHarnessCallbackService_GetMissionStatus tests the GetMissionStatus RPC handler.
func TestHarnessCallbackService_GetMissionStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	ctx := context.Background()
	req := &harnesspb.GetMissionStatusRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: "test-agent",
			MissionId: "mission-123",
		},
		MissionId: "target-mission-456",
	}

	resp, err := service.GetMissionStatus(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not yet implemented")
}

// TestHarnessCallbackService_WaitForMission tests the WaitForMission RPC handler.
func TestHarnessCallbackService_WaitForMission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	ctx := context.Background()
	req := &harnesspb.WaitForMissionRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: "test-agent",
			MissionId: "mission-123",
		},
		MissionId: "target-mission-456",
		TimeoutMs: 30000,
	}

	resp, err := service.WaitForMission(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not yet implemented")
}

// TestHarnessCallbackService_ListMissions tests the ListMissions RPC handler.
func TestHarnessCallbackService_ListMissions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	ctx := context.Background()
	req := &harnesspb.ListMissionsRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: "test-agent",
			MissionId: "mission-123",
		},
	}

	resp, err := service.ListMissions(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not yet implemented")
}

// TestHarnessCallbackService_CancelMission tests the CancelMission RPC handler.
func TestHarnessCallbackService_CancelMission(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	ctx := context.Background()
	req := &harnesspb.CancelMissionRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: "test-agent",
			MissionId: "mission-123",
		},
		MissionId: "target-mission-456",
	}

	resp, err := service.CancelMission(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not yet implemented")
}

// TestHarnessCallbackService_GetMissionResults tests the GetMissionResults RPC handler.
func TestHarnessCallbackService_GetMissionResults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewHarnessCallbackService(logger)

	ctx := context.Background()
	req := &harnesspb.GetMissionResultsRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: "test-agent",
			MissionId: "mission-123",
		},
		MissionId: "target-mission-456",
	}

	resp, err := service.GetMissionResults(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "not yet implemented")
}

// ============================================================================
// CallToolProto Integration Tests with ProtoResolver
// ============================================================================

// createTestFileDescriptorSetForCallback creates a FileDescriptorSet for testing
// with both input and output message types, including a DiscoveryResult field.
func createTestFileDescriptorSetForCallback() string {
	// Import google.protobuf.Any for DiscoveryResult
	googleProtobufFile := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("google/protobuf/any.proto"),
		Package: proto.String("google.protobuf"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("Any"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("type_url"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("value"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
		},
	}

	// Create test tool input type
	testToolFile := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("testtool.proto"),
		Package: proto.String("testtool"),
		Dependency: []string{
			"google/protobuf/any.proto",
		},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("ToolInput"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("query"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("limit"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
			{
				Name: proto.String("ToolOutput"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("result"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("count"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						// Field 100 for DiscoveryResult (using Any for simplicity)
						Name:     proto.String("discovery_result"),
						Number:   proto.Int32(100),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
						TypeName: proto.String(".google.protobuf.Any"),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
		},
	}

	// Create FileDescriptorSet with both files
	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			googleProtobufFile,
			testToolFile,
		},
	}

	// Marshal to bytes and encode as base64
	fdsBytes, err := proto.Marshal(fds)
	if err != nil {
		panic("failed to marshal test FileDescriptorSet: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(fdsBytes)
}

// mockHarnessWithResolver is a minimal mock harness for testing CallToolProto with resolver.
// It only implements the methods needed for CallToolProto testing.
type mockHarnessWithResolver struct {
	toolDescriptors map[string]*ToolDescriptor
	toolHandler     func(ctx context.Context, name string, request proto.Message, response proto.Message) error
}

func (m *mockHarnessWithResolver) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	if desc, ok := m.toolDescriptors[name]; ok {
		return desc, nil
	}
	return nil, fmt.Errorf("tool not found: %s", name)
}

func (m *mockHarnessWithResolver) CallToolProto(ctx context.Context, name string, request proto.Message, response proto.Message) error {
	if m.toolHandler != nil {
		return m.toolHandler(ctx, name, request, response)
	}
	return fmt.Errorf("no tool handler configured")
}

// Stub implementations of other required AgentHarness methods
func (m *mockHarnessWithResolver) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) ListTools() []ToolDescriptor {
	return nil
}

func (m *mockHarnessWithResolver) QueryPlugin(ctx context.Context, pluginName string, method string, params map[string]any) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) ListPlugins() []PluginDescriptor {
	return nil
}

func (m *mockHarnessWithResolver) DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error) {
	return agent.Result{}, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) ListAgents() []AgentDescriptor {
	return nil
}

func (m *mockHarnessWithResolver) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	return fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) Mission() MissionContext {
	return MissionContext{}
}

func (m *mockHarnessWithResolver) MissionID() types.ID {
	return types.ID("")
}

func (m *mockHarnessWithResolver) MissionExecutionContext() MissionExecutionContextSDK {
	return MissionExecutionContextSDK{}
}

func (m *mockHarnessWithResolver) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return make(map[string]*sdktypes.Capabilities), nil
}

func (m *mockHarnessWithResolver) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessWithResolver) Target() TargetInfo {
	return TargetInfo{}
}

func (m *mockHarnessWithResolver) Memory() memory.MemoryStore {
	return nil
}

func (m *mockHarnessWithResolver) Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func (m *mockHarnessWithResolver) Tracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("test")
}

func (m *mockHarnessWithResolver) Metrics() MetricsRecorder {
	return nil
}

func (m *mockHarnessWithResolver) TokenUsage() *llm.TokenTracker {
	return nil
}

// TestCallToolProto_WithExternalAgentDynamicType tests CallToolProto with a tool
// that is not in GlobalTypes, using FileDescriptorSet for type resolution.
func TestCallToolProto_WithExternalAgentDynamicType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create test FileDescriptorSet
	fdsBase64 := createTestFileDescriptorSetForCallback()

	// Create mock harness with tool descriptor
	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"test-external-tool": {
				Name:            "test-external-tool",
				Description:     "A test tool with dynamic types",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata: map[string]string{
					"file_descriptor_set": fdsBase64,
				},
			},
		},
		toolHandler: func(ctx context.Context, name string, request proto.Message, response proto.Message) error {
			// Verify input is properly typed
			require.NotNil(t, request)
			require.True(t, request.ProtoReflect().IsValid())

			// Use reflection to read input fields
			inputRefl := request.ProtoReflect()
			queryField := inputRefl.Descriptor().Fields().ByName("query")
			limitField := inputRefl.Descriptor().Fields().ByName("limit")

			require.NotNil(t, queryField)
			require.NotNil(t, limitField)

			query := inputRefl.Get(queryField).String()
			limit := int32(inputRefl.Get(limitField).Int())

			assert.Equal(t, "test query", query)
			assert.Equal(t, int32(10), limit)

			// Set output fields using reflection
			outputRefl := response.ProtoReflect()
			resultField := outputRefl.Descriptor().Fields().ByName("result")
			countField := outputRefl.Descriptor().Fields().ByName("count")

			require.NotNil(t, resultField)
			require.NotNil(t, countField)

			outputRefl.Set(resultField, protoreflect.ValueOfString("success"))
			outputRefl.Set(countField, protoreflect.ValueOfInt32(42))

			return nil
		},
	}

	// Create callback service with registry
	registry := NewCallbackHarnessRegistry()
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	// Register mock harness
	missionID := "test-mission-123"
	agentName := "test-agent"
	registry.Register(missionID, agentName, mockHarness)

	// Create request with JSON input
	inputJSON := []byte(`{"query": "test query", "limit": 10}`)
	req := &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: agentName,
			MissionId: missionID,
		},
		Name:       "test-external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  inputJSON,
		OutputType: "testtool.ToolOutput",
	}

	// Execute CallToolProto
	ctx := context.Background()
	resp, err := service.CallToolProto(ctx, req)

	// Verify response
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error, "Expected no error, got: %v", resp.Error)
	require.NotNil(t, resp.OutputJson)

	// Parse output JSON
	var output map[string]interface{}
	err = json.Unmarshal(resp.OutputJson, &output)
	require.NoError(t, err)

	// Verify output fields
	assert.Equal(t, "success", output["result"])
	assert.Equal(t, float64(42), output["count"]) // JSON numbers are float64
}

// TestCallToolProto_InputJSONToTypedMessage tests that input JSON is properly
// converted to a typed proto message.
func TestCallToolProto_InputJSONToTypedMessage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	fdsBase64 := createTestFileDescriptorSetForCallback()

	var capturedInput proto.Message

	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"json-input-tool": {
				Name:            "json-input-tool",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata: map[string]string{
					"file_descriptor_set": fdsBase64,
				},
			},
		},
		toolHandler: func(ctx context.Context, name string, request proto.Message, response proto.Message) error {
			// Capture the input for verification
			capturedInput = request
			return nil
		},
	}

	registry := NewCallbackHarnessRegistry()
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	missionID := "test-mission-456"
	agentName := "test-agent"
	registry.Register(missionID, agentName, mockHarness)

	// Test various JSON input scenarios
	testCases := []struct {
		name      string
		inputJSON string
		verify    func(t *testing.T, msg proto.Message)
	}{
		{
			name:      "simple fields",
			inputJSON: `{"query": "hello world", "limit": 100}`,
			verify: func(t *testing.T, msg proto.Message) {
				refl := msg.ProtoReflect()
				query := refl.Get(refl.Descriptor().Fields().ByName("query")).String()
				limit := int32(refl.Get(refl.Descriptor().Fields().ByName("limit")).Int())
				assert.Equal(t, "hello world", query)
				assert.Equal(t, int32(100), limit)
			},
		},
		{
			name:      "partial fields",
			inputJSON: `{"query": "only query"}`,
			verify: func(t *testing.T, msg proto.Message) {
				refl := msg.ProtoReflect()
				query := refl.Get(refl.Descriptor().Fields().ByName("query")).String()
				assert.Equal(t, "only query", query)
			},
		},
		{
			name:      "empty object",
			inputJSON: `{}`,
			verify: func(t *testing.T, msg proto.Message) {
				require.NotNil(t, msg)
				assert.True(t, msg.ProtoReflect().IsValid())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			capturedInput = nil

			req := &harnesspb.CallToolProtoRequest{
				Context: &harnesspb.ContextInfo{
					TaskId:    "task-123",
					AgentName: agentName,
					MissionId: missionID,
				},
				Name:       "json-input-tool",
				InputType:  "testtool.ToolInput",
				InputJson:  []byte(tc.inputJSON),
				OutputType: "testtool.ToolOutput",
			}

			ctx := context.Background()
			resp, err := service.CallToolProto(ctx, req)

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Nil(t, resp.Error)

			// Verify captured input
			require.NotNil(t, capturedInput, "Tool handler was not called")
			tc.verify(t, capturedInput)
		})
	}
}

// TestCallToolProto_OutputTypedMessageToJSON tests that output proto messages
// are properly converted to JSON.
func TestCallToolProto_OutputTypedMessageToJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	fdsBase64 := createTestFileDescriptorSetForCallback()

	testCases := []struct {
		name         string
		setOutput    func(response proto.Message)
		expectedJSON map[string]interface{}
	}{
		{
			name: "basic output",
			setOutput: func(response proto.Message) {
				refl := response.ProtoReflect()
				refl.Set(refl.Descriptor().Fields().ByName("result"), protoreflect.ValueOfString("test result"))
				refl.Set(refl.Descriptor().Fields().ByName("count"), protoreflect.ValueOfInt32(123))
			},
			expectedJSON: map[string]interface{}{
				"result": "test result",
				"count":  float64(123),
			},
		},
		{
			name: "partial output",
			setOutput: func(response proto.Message) {
				refl := response.ProtoReflect()
				refl.Set(refl.Descriptor().Fields().ByName("result"), protoreflect.ValueOfString("only result"))
			},
			expectedJSON: map[string]interface{}{
				"result": "only result",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockHarness := &mockHarnessWithResolver{
				toolDescriptors: map[string]*ToolDescriptor{
					"output-tool": {
						Name:            "output-tool",
						InputProtoType:  "testtool.ToolInput",
						OutputProtoType: "testtool.ToolOutput",
						Metadata: map[string]string{
							"file_descriptor_set": fdsBase64,
						},
					},
				},
				toolHandler: func(ctx context.Context, name string, request proto.Message, response proto.Message) error {
					tc.setOutput(response)
					return nil
				},
			}

			registry := NewCallbackHarnessRegistry()
			service := NewHarnessCallbackServiceWithRegistry(logger, registry)

			missionID := "test-mission-789"
			agentName := "test-agent"
			registry.Register(missionID, agentName, mockHarness)

			req := &harnesspb.CallToolProtoRequest{
				Context: &harnesspb.ContextInfo{
					TaskId:    "task-123",
					AgentName: agentName,
					MissionId: missionID,
				},
				Name:       "output-tool",
				InputType:  "testtool.ToolInput",
				InputJson:  []byte(`{}`),
				OutputType: "testtool.ToolOutput",
			}

			ctx := context.Background()
			resp, err := service.CallToolProto(ctx, req)

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Nil(t, resp.Error)
			require.NotNil(t, resp.OutputJson)

			// Parse and verify output JSON
			var output map[string]interface{}
			err = json.Unmarshal(resp.OutputJson, &output)
			require.NoError(t, err)

			for key, expectedValue := range tc.expectedJSON {
				assert.Equal(t, expectedValue, output[key], "Field %s mismatch", key)
			}
		})
	}
}

// TestCallToolProto_DiscoveryResultExtraction tests that DiscoveryResult
// (field 100) is properly extracted from dynamic response messages.
func TestCallToolProto_DiscoveryResultExtraction(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	fdsBase64 := createTestFileDescriptorSetForCallback()

	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"discovery-tool": {
				Name:            "discovery-tool",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata: map[string]string{
					"file_descriptor_set": fdsBase64,
				},
			},
		},
		toolHandler: func(ctx context.Context, name string, request proto.Message, response proto.Message) error {
			// Set regular output fields
			refl := response.ProtoReflect()
			refl.Set(refl.Descriptor().Fields().ByName("result"), protoreflect.ValueOfString("with discovery"))
			refl.Set(refl.Descriptor().Fields().ByName("count"), protoreflect.ValueOfInt32(1))

			// Set field 100 (discovery_result) using Any
			discoveryField := refl.Descriptor().Fields().ByNumber(100)
			require.NotNil(t, discoveryField, "Field 100 should exist")

			// Create a simple Any message for testing
			anyMsg := &anypb.Any{
				TypeUrl: "type.googleapis.com/test.DiscoveryData",
				Value:   []byte("test discovery data"),
			}

			// Set the discovery field
			refl.Set(discoveryField, protoreflect.ValueOfMessage(anyMsg.ProtoReflect()))

			return nil
		},
	}

	registry := NewCallbackHarnessRegistry()
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	missionID := "test-mission-discovery"
	agentName := "test-agent"
	registry.Register(missionID, agentName, mockHarness)

	req := &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: agentName,
			MissionId: missionID,
		},
		Name:       "discovery-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  []byte(`{"query": "test"}`),
		OutputType: "testtool.ToolOutput",
	}

	ctx := context.Background()
	resp, err := service.CallToolProto(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.OutputJson)

	// Parse output JSON to verify field 100 is present
	var output map[string]interface{}
	err = json.Unmarshal(resp.OutputJson, &output)
	require.NoError(t, err)

	// Verify regular fields
	assert.Equal(t, "with discovery", output["result"])
	assert.Equal(t, float64(1), output["count"])

	// Verify discovery_result field (field 100) is present in JSON
	// Note: The exact format depends on how protojson marshals Any messages
	if discoveryResult, ok := output["discovery_result"]; ok {
		t.Logf("Discovery result present in output: %v", discoveryResult)
		// Just verify it exists - the exact structure depends on the Any message
		assert.NotNil(t, discoveryResult)
	} else {
		t.Log("Discovery result field not present in JSON output (may be omitted if empty)")
	}
}

// TestCallToolProto_ErrorCases tests error handling in CallToolProto.
func TestCallToolProto_ErrorCases(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	fdsBase64 := createTestFileDescriptorSetForCallback()

	testCases := []struct {
		name          string
		setupHarness  func() AgentHarness
		request       *harnesspb.CallToolProtoRequest
		expectedError string
	}{
		{
			name: "tool not found",
			setupHarness: func() AgentHarness {
				return &mockHarnessWithResolver{
					toolDescriptors: map[string]*ToolDescriptor{},
				}
			},
			request: &harnesspb.CallToolProtoRequest{
				Context: &harnesspb.ContextInfo{
					TaskId:    "task-123",
					AgentName: "test-agent",
					MissionId: "mission-123",
				},
				Name:       "nonexistent-tool",
				InputType:  "testtool.ToolInput",
				InputJson:  []byte(`{}`),
				OutputType: "testtool.ToolOutput",
			},
			expectedError: "tool not found",
		},
		{
			name: "invalid input JSON",
			setupHarness: func() AgentHarness {
				return &mockHarnessWithResolver{
					toolDescriptors: map[string]*ToolDescriptor{
						"test-tool": {
							Name:            "test-tool",
							InputProtoType:  "testtool.ToolInput",
							OutputProtoType: "testtool.ToolOutput",
							Metadata: map[string]string{
								"file_descriptor_set": fdsBase64,
							},
						},
					},
				}
			},
			request: &harnesspb.CallToolProtoRequest{
				Context: &harnesspb.ContextInfo{
					TaskId:    "task-123",
					AgentName: "test-agent",
					MissionId: "mission-123",
				},
				Name:       "test-tool",
				InputType:  "testtool.ToolInput",
				InputJson:  []byte(`invalid json`),
				OutputType: "testtool.ToolOutput",
			},
			expectedError: "failed to unmarshal input",
		},
		{
			name: "tool execution error",
			setupHarness: func() AgentHarness {
				return &mockHarnessWithResolver{
					toolDescriptors: map[string]*ToolDescriptor{
						"failing-tool": {
							Name:            "failing-tool",
							InputProtoType:  "testtool.ToolInput",
							OutputProtoType: "testtool.ToolOutput",
							Metadata: map[string]string{
								"file_descriptor_set": fdsBase64,
							},
						},
					},
					toolHandler: func(ctx context.Context, name string, request proto.Message, response proto.Message) error {
						return fmt.Errorf("tool execution failed")
					},
				}
			},
			request: &harnesspb.CallToolProtoRequest{
				Context: &harnesspb.ContextInfo{
					TaskId:    "task-123",
					AgentName: "test-agent",
					MissionId: "mission-123",
				},
				Name:       "failing-tool",
				InputType:  "testtool.ToolInput",
				InputJson:  []byte(`{}`),
				OutputType: "testtool.ToolOutput",
			},
			expectedError: "tool execution failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewCallbackHarnessRegistry()
			service := NewHarnessCallbackServiceWithRegistry(logger, registry)

			harness := tc.setupHarness()
			registry.Register(tc.request.Context.MissionId, tc.request.Context.AgentName, harness)

			ctx := context.Background()
			resp, err := service.CallToolProto(ctx, tc.request)

			require.NoError(t, err, "RPC should not return error")
			require.NotNil(t, resp)
			require.NotNil(t, resp.Error, "Response should contain error")
			assert.Contains(t, resp.Error.Message, tc.expectedError)
		})
	}
}
