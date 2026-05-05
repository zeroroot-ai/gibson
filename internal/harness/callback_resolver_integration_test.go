//go:build integration

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
	sdkagent "github.com/zero-day-ai/sdk/agent"
	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// createTestFDSForIntegration creates a FileDescriptorSet for integration testing
func createTestFDSForIntegration() string {
	// Import google.protobuf.Any
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

	// Create test tool types
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
						// Field 100 for DiscoveryResult
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

	fds := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			googleProtobufFile,
			testToolFile,
		},
	}

	fdsBytes, err := proto.Marshal(fds)
	if err != nil {
		panic("failed to marshal test FileDescriptorSet: " + err.Error())
	}

	return base64.StdEncoding.EncodeToString(fdsBytes)
}

// mockHarnessForResolver is a minimal mock for testing CallToolProto with resolver
type mockHarnessForResolver struct {
	toolDescriptors map[string]*ToolDescriptor
	toolHandler     func(ctx context.Context, name string, request proto.Message, response proto.Message) error
}

func (m *mockHarnessForResolver) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	if desc, ok := m.toolDescriptors[name]; ok {
		return desc, nil
	}
	return nil, fmt.Errorf("tool not found: %s", name)
}

func (m *mockHarnessForResolver) CallToolProto(ctx context.Context, name string, request proto.Message, response proto.Message) error {
	if m.toolHandler != nil {
		return m.toolHandler(ctx, name, request, response)
	}
	return fmt.Errorf("no tool handler configured")
}

func (m *mockHarnessForResolver) CallToolProtoStream(ctx context.Context, name string, request proto.Message, response proto.Message, callback sdkagent.ToolStreamCallback) error {
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

// Stub implementations
func (m *mockHarnessForResolver) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) ListTools() []ToolDescriptor {
	return nil
}

func (m *mockHarnessForResolver) QueryPlugin(ctx context.Context, pluginName string, method string, params map[string]any) (any, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) ListPlugins() []PluginDescriptor {
	return nil
}

func (m *mockHarnessForResolver) DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error) {
	return agent.Result{}, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) ListAgents() []AgentDescriptor {
	return nil
}

func (m *mockHarnessForResolver) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	return fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) Mission() MissionContext {
	return MissionContext{}
}

func (m *mockHarnessForResolver) MissionID() types.ID {
	return types.ID("")
}

func (m *mockHarnessForResolver) MissionExecutionContext() MissionExecutionContextSDK {
	return MissionExecutionContextSDK{}
}

func (m *mockHarnessForResolver) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return make(map[string]*sdktypes.Capabilities), nil
}

func (m *mockHarnessForResolver) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockHarnessForResolver) Target() TargetInfo {
	return TargetInfo{}
}

func (m *mockHarnessForResolver) Memory() memory.MemoryStore {
	return nil
}

func (m *mockHarnessForResolver) Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func (m *mockHarnessForResolver) Tracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("test")
}

func (m *mockHarnessForResolver) Metrics() MetricsRecorder {
	return nil
}

func (m *mockHarnessForResolver) TokenUsage() *llm.TokenTracker {
	return nil
}

// TestCallbackServiceWithProtoResolver_Integration tests end-to-end flow with ProtoResolver
func TestCallbackServiceWithProtoResolver_Integration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	fdsBase64 := createTestFDSForIntegration()

	// Track what was received by the tool
	var capturedInput proto.Message

	mockHarness := &mockHarnessForResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			"external-tool": {
				Name:            "external-tool",
				Description:     "External tool with dynamic types",
				InputProtoType:  "testtool.ToolInput",
				OutputProtoType: "testtool.ToolOutput",
				Metadata: map[string]string{
					"file_descriptor_set": fdsBase64,
				},
			},
		},
		toolHandler: func(ctx context.Context, name string, request proto.Message, response proto.Message) error {
			capturedInput = request

			// Read input using reflection
			inputRefl := request.ProtoReflect()
			queryField := inputRefl.Descriptor().Fields().ByName("query")
			limitField := inputRefl.Descriptor().Fields().ByName("limit")

			query := inputRefl.Get(queryField).String()
			limit := int32(inputRefl.Get(limitField).Int())

			t.Logf("Tool received: query=%s, limit=%d", query, limit)

			// Set output using reflection
			outputRefl := response.ProtoReflect()
			outputRefl.Set(outputRefl.Descriptor().Fields().ByName("result"), protoreflect.ValueOfString("processed: "+query))
			outputRefl.Set(outputRefl.Descriptor().Fields().ByName("count"), protoreflect.ValueOfInt32(limit*2))

			// Set discovery field (field 100)
			discoveryField := outputRefl.Descriptor().Fields().ByNumber(100)
			if discoveryField != nil {
				anyMsg := &anypb.Any{
					TypeUrl: "type.googleapis.com/test.Discovery",
					Value:   []byte("discovery data"),
				}
				outputRefl.Set(discoveryField, protoreflect.ValueOfMessage(anyMsg.ProtoReflect()))
			}

			return nil
		},
	}

	// Create service and registry
	registry := NewCallbackHarnessRegistry()
	service := NewHarnessCallbackServiceWithRegistry(logger, registry)

	missionID := "integration-mission-123"
	agentName := "integration-agent"
	registry.Register(missionID, agentName, mockHarness)

	// Create request
	inputJSON := []byte(`{"query": "test query", "limit": 10}`)
	req := &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:    "task-123",
			AgentName: agentName,
			MissionId: missionID,
		},
		Name:       "external-tool",
		InputType:  "testtool.ToolInput",
		InputJson:  inputJSON,
		OutputType: "testtool.ToolOutput",
	}

	// Execute
	ctx := context.Background()
	resp, err := service.CallToolProto(ctx, req)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error, "Expected no error, got: %v", resp.Error)
	require.NotNil(t, resp.OutputJson)

	// Verify input was captured
	require.NotNil(t, capturedInput)
	assert.True(t, capturedInput.ProtoReflect().IsValid())

	// Parse and verify output
	var output map[string]interface{}
	err = json.Unmarshal(resp.OutputJson, &output)
	require.NoError(t, err)

	assert.Equal(t, "processed: test query", output["result"])
	assert.Equal(t, float64(20), output["count"])

	t.Logf("Test passed! Output: %s", string(resp.OutputJson))
}
